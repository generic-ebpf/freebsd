#include "ebpf_platform.h"
#include <sys/ebpf.h>

/*
 * Character device frontend of eBPF
 */

/*
 * Global lock
 */
static struct mtx ebpf_global_mtx;

#define EBPF_DEV_GLOBAL_LOCK_INIT() \
	mtx_init(&ebpf_global_mtx, "ebpf_global_mtx", NULL, MTX_DEF)
#define EBPF_DEV_GLOBAL_LOCK_DESTROY() mtx_destroy(&ebpf_global_mtx);
#define EBPF_DEV_GLOBAL_LOCK() mtx_lock(&ebpf_global_mtx)
#define EBPF_DEV_GLOBAL_UNLOCK() mtx_unlock(&ebpf_global_mtx)
#define EBPF_DEV_GLOBAL_LOCK_ASSERT() mtx_assert(&ebpf_global_mtx, MA_OWNED)

/*
 * Flag to indicate the module is under draining or not
 */
static bool draining;

/*
 * Reference count to this module
 */
static u_int ebpf_global_refcount;

/*
 * User must hold a ebpf_global_mtx to access to this array.
 * Each opened /dev/ebpf files holds the local copy of this
 * structure and take a reference count of each environments.
 */
static struct ebpf_env *ebpf_global_envs[EBPF_ENV_MAX];

/*
 * Common file operations for the eBPF object files.
 */
static struct fileops ebpf_obj_file_ops;

static __inline void
global_acquire(void)
{
	refcount_acquire(&ebpf_global_refcount);
}

static __inline bool
global_release(void)
{
	return refcount_release(&ebpf_global_refcount);
}

static bool
no_user(void)
{
	return (REFCOUNT_COUNT(ebpf_global_refcount) == 0);
}

int
ebpf_env_register(uint32_t id, struct ebpf_env *ee)
{
	int error = 0;

	if (id >= EBPF_ENV_MAX || ee == NULL)
		return (EINVAL);

	EBPF_GLOBAL_LOCK();

	if (!draining) {
		if (ebpf_global_envs[id] == NULL) {
			ebpf_env_acquire(ee);
			ebpf_global_envs[id] = ee;
		} else {
			error = EINVAL;
		}
	} else {
		error = EPERM;
	}

	EBPF_GLOBAL_UNLOCK();

	return (error);
}

struct ebpf_env *
ebpf_env_unregister(uint32_t id)
{
	struct ebpf_env *ee;

	if (id >= EBPF_ENV_MAX)
		return (NULL);

	EBPF_GLOBAL_LOCK();
	if (ebpf_global_envs[id] != NULL)
		ee = ebpf_global_envs[id];
	else
		ee = NULL;
	EBPF_GLOBAL_UNLOCK();

	ebpf_env_release(ee);

	return (ee);
}

static int
copyin_alloc(const void *uaddr, void **kaddrp, size_t len)
{
	void *p;
	int error;

	p = ebpf_malloc(len);
	if (p == NULL)
		return (ENOMEM);

	error = copyin(uaddr, p, len);
	if (error != 0) {
		ebpf_free(p);
		return error;
	}

	*kaddrp = p;

	return (0);
}

/*
 * Context struct which is private to all of the
 * /dev/ebpf file descriptor
 */
struct ebpf_dev_ctx {
	/* 
	 * Local snapshot of the ebpf_global_envs
	 */
	struct ebpf_env *local_envs[EBPF_ENV_MAX];
};

static void
ebpf_dev_ctx_clone_global_envs(struct ebpf_dev_ctx *edc)
{
	struct ebpf_env *ee;

	/*
	 * Take a reference to the environments and copy it to the local
	 * context. Otherwise, fill with NULL.
	 */
	for (uint32_t i = 0; i < EBPF_ENV_MAX; i++) {
		ee = ebpf_global_envs[i];
		if (ee != NULL) {
			ebpf_env_acquire(ee);
			edc->local_envs[i] = ee;
		} else {
			edc->local_envs[i] = NULL;
		}
	}
}

static void
ebpf_dev_ctx_unclone_global_envs(struct ebpf_dev_ctx *edc)
{
	struct ebpf_env *ee;

	for (uint32_t i = 0; i < EBPF_ENV_MAX; i++) {
		ee = edc->local_envs[i];
		if (ee != NULL) {
			ebpf_env_release(ee);
		}
	}
}

static int
ebpf_dev_ctx_create(struct ebpf_dev_ctx **edcp)
{
	struct ebpf_dev_ctx *ret;

	ret = ebpf_malloc(sizeof(*ret));
	if (ret == NULL)
		return (ENOMEM);

	EBPF_DEV_GLOBAL_LOCK();

	ebpf_dev_ctx_clone_global_envs(ret);

	EBPF_DEV_GLOBAL_UNLOCK();

	*edcp = ret;

	return (0);
}

static void
ebpf_dev_ctx_destroy(struct ebpf_dev_ctx *edc)
{
	ebpf_dev_ctx_unclone_global_envs(edc);
	ebpf_free(edc);
}

static struct ebpf_env *
ebpf_dev_ctx_get_env(struct ebpf_dev_ctx *edc, uint32_t id)
{
	if (id >= EBPF_ENV_MAX)
		return (NULL);

	return (edc->local_envs[id]);
}

static struct ebpf_dev_ctx *
ebpf_dev_get_ctx(struct cdev *cdev)
{
	int error;
	struct ebpf_dev_ctx *edc;

	error = devfs_get_cdevpriv((void **)&edc);
	KASSERT(error == 0, "ebpf_dev file descriptor doesn't have ctx");

	return edc;
}

/*
 * Open new file and bind the given eBPF object to it.
 * Once this function succeeds, the ownership of the
 * eBPF object moves to the file and users aren't
 * responsible to release it. It is automatically
 * released when the file is closed.
 */
static int
ebpf_obj_file_open(struct thread *td, struct file **fpp, int *fdp,
		struct ebpf_obj *data)
{
	int error;

	error = falloc(td, fpp, fdp, 0);
	if (error != 0)
		return (error);

	finit(*fpp, FREAD | FWRITE, DTYPE_NONE, data, &ebpf_obj_file_ops);

	global_acquire();

	return (0);
}

/*
 * Called on evey close(2). When it is the last close(2) for
 * that file, we can release the eBPF object assosiated with
 * the file.
 */
static int
ebpf_obj_file_close(struct file *fp, struct thread *td)
{
	struct ebpf_obj *eo = fp->f_data;

	if (fp->f_count == 0) {
		ebpf_obj_release(eo);
		global_release();
	}

	return (0);
}

static int
ebpf_obj_fget(struct thread *td, int fd, struct file **fpp)
{
	int error;

	error = fget(td, fd, &cap_ioctl_rights, fpp);
	if (error != 0)
		return (error);

	/*
	 * This is only the way to see what kind of
	 * the file it is.
	 */
	if ((*fpp)->f_ops != &ebpf_obj_file_ops) {
		error = EINVAL;
		goto err0;
	}

	return (error);

err0:
	fdrop(*fpp, td);
	return (error);
}

static int
ebpf_ioc_load_prog(struct cdev *cdev, caddr_t data, struct thread *td)
{
	int error, fd;
	struct file *fp;
	struct ebpf_env *ee;
	struct ebpf_prog *ep;
	struct ebpf_inst *prog;
	struct ebpf_prog_attr attr;
	struct ebpf_dev_ctx *edc =
		ebpf_dev_get_ctx(cdev);
	struct ebpf_load_prog_req *req =
		(struct ebpf_load_prog_req *)data;

	if (req->fdp == NULL || req->env >= EBPF_ENV_MAX ||
			req->prog_len > EBPF_PROG_LEN_MAX)
		return (EINVAL);

	ee = ebpf_dev_ctx_get_env(edc, req->env);
	if (ee != NULL)
		return (ENOENT);

	error = copyin_alloc(req->prog, (void **)&prog, req->prog_len);
	if (error != 0)
		return (error);

	attr.type = req->type;
	attr.prog = prog;
	attr.prog_len = req->prog_len;

	error = ebpf_prog_create(ee, &ep, &attr);
	if (error != 0)
		goto err0;

	error = ebpf_obj_file_open(td, &fp, &fd, (struct ebpf_obj *)&prog);
	if (error != 0)
		goto err1;

	error = copyout(&fd, req->fdp, sizeof(fd));
	if (error != 0)
		goto err2;

err2:
	ebpf_free(prog);
	fdrop(fp, td);
	return (error);
err1:
	ebpf_prog_destroy(ep);
err0:
	ebpf_free(prog);
	return (error);
}

static int
ebpf_ioc_map_create(struct cdev *cdev, caddr_t data, struct thread *td)
{
	int error, fd;
	struct file *fp;
	struct ebpf_env *ee;
	struct ebpf_map *em;
	struct ebpf_map_attr attr;
	struct ebpf_dev_ctx *edc =
		ebpf_dev_get_ctx(cdev);
	struct ebpf_map_create_req *req =
		(struct ebpf_map_create_req *)data;

	if (req->fdp == NULL || req->env >= EBPF_ENV_MAX)
		return (EINVAL);

	ee = ebpf_dev_ctx_get_env(edc, req->env);
	if (ee != NULL)
		return (ENOENT);

	attr.type = req->type;
	attr.key_size = req->key_size;
	attr.value_size = req->value_size;
	attr.max_entries = req->max_entries;
	attr.flags = req->flags;

	error = ebpf_map_create(ee, &em, &attr);
	if (error != 0)
		return (error);

  error = ebpf_obj_file_open(td, &fp, &fd, (struct ebpf_obj *)em);
	if (error != 0)
		goto err0;

	error = copyout(&fd, req->fdp, sizeof(fd));
	if (error != 0)
		goto err1;

err1:
	fdrop(fp, td);
	return (error);
err0:
	ebpf_map_destroy(em);
	return (error);
}

static int
ebpf_ioc_map_lookup_elem(caddr_t data, struct thread *td)
{
	int error;
	void *k, *v;
	struct file *fp;
	struct ebpf_map *em;
	struct ebpf_map_lookup_req *req =
		(struct ebpf_map_lookup_req *)data;

	error = ebpf_obj_fget(td, req->fd, &fp);
	if (error != 0)
		return (error);

	em = (struct ebpf_map *)fp->f_data;
	if (em == NULL || em->eo.eo_type != EBPF_OBJ_TYPE_MAP) {
		error = EINVAL;
		goto err0;
	}

	error = copyin_alloc(req->key, &k, em->key_size); 
	if (error != 0)
		goto err0;

	v = ebpf_malloc(em->value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_map_lookup_elem_from_user(em, k, v);
	if (error != 0)
		goto err2;

	error = copyout(v, req->value, em->value_size);
	if (error != 0)
		goto err2;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	fdrop(fp, td);
	return (error);
}

static int
ebpf_ioc_map_update_elem(caddr_t data, struct thread *td)
{
	int error;
	void *k, *v;
	struct file *fp;
	struct ebpf_map *em;
	struct ebpf_map_update_req *req =
		(struct ebpf_map_update_req *)data;

	error = ebpf_obj_fget(td, req->fd, &fp);
	if (error != 0)
		return (error);

	em = (struct ebpf_map *)fp->f_data;
	if (em == NULL || em->eo.eo_type != EBPF_OBJ_TYPE_MAP) {
		error = EINVAL;
		goto err0;
	}

	error = copyin_alloc(req->key, &k, em->key_size); 
	if (error != 0)
		goto err0;

	error = copyin_alloc(req->value, &v, em->value_size); 
	if (error != 0)
		goto err1;

	error = ebpf_map_update_elem_from_user(em, k, v, req->flags);
	if (error != 0)
		goto err2;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	fdrop(fp, td);
	return (error);
}

static int
ebpf_ioc_map_delete_elem(caddr_t data, struct thread *td)
{
	int error;
	void *k;
	struct file *fp;
	struct ebpf_map *em;
	struct ebpf_map_delete_req *req =
		(struct ebpf_map_delete_req *)data;

	error = ebpf_obj_fget(td, req->fd, &fp);
	if (error != 0)
		return (error);

	em = (struct ebpf_map *)fp->f_data;
	if (em == NULL || em->eo.eo_type != EBPF_OBJ_TYPE_MAP) {
		error = EINVAL;
		goto err0;
	}

	error = copyin_alloc(req->key, &k, em->key_size); 
	if (error != 0)
		goto err0;

	error = ebpf_map_delete_elem_from_user(em, k);
	if (error != 0)
		goto err1;

err1:
	ebpf_free(k);
err0:
	fdrop(fp, td);
	return (error);
}

static int
ebpf_ioc_map_get_next_key(caddr_t data, struct thread *td)
{
	int error;
	void *k, *nk;
	struct file *fp;
	struct ebpf_map *em;
	struct ebpf_map_get_next_key_req *req =
		(struct ebpf_map_get_next_key_req *)data;

	error = ebpf_obj_fget(td, req->fd, &fp);
	if (error != 0)
		return (error);

	em = (struct ebpf_map *)fp->f_data;
	if (em == NULL || em->eo.eo_type != EBPF_OBJ_TYPE_MAP) {
		error = EINVAL;
		goto err0;
	}

	error = copyin_alloc(req->key, &k, em->key_size); 
	if (error != 0)
		goto err0;

	nk = ebpf_malloc(em->key_size);
	if (nk == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_map_get_next_key_from_user(em, k, nk);
	if (error != 0)
		goto err2;

	error = copyout(nk, req->next_key, em->key_size);
	if (error != 0)
		goto err2;

err2:
	ebpf_free(nk);
err1:
	ebpf_free(k);
err0:
	fdrop(fp, td);
	return (error);
}

static int
ebpf_ioctl(struct cdev *cdev, u_long cmd, caddr_t data,
		int flag, struct thread *td)
{
	int error;
	
	if (data == NULL)
		return (EINVAL);
	
	switch (cmd) {
	case EBPFIOC_LOAD_PROG:
		error = ebpf_ioc_load_prog(cdev, data, td);
		break;
	case EBPFIOC_MAP_CREATE:
		error = ebpf_ioc_map_create(cdev, data, td);
		break;
	case EBPFIOC_MAP_LOOKUP_ELEM:
		error = ebpf_ioc_map_lookup_elem(data, td);
		break;
	case EBPFIOC_MAP_UPDATE_ELEM:
		error = ebpf_ioc_map_update_elem(data, td);
		break;
	case EBPFIOC_MAP_DELETE_ELEM:
		error = ebpf_ioc_map_delete_elem(data, td);
		break;
	case EBPFIOC_MAP_GET_NEXT_KEY:
		error = ebpf_ioc_map_get_next_key(data, td);
		break;
	default:
		error = EINVAL;
		break;
	}

	return error;
}

static void
ebpf_dev_ctx_dtor(void *data)
{
	ebpf_dev_ctx_destroy(data);
}

static int
ebpf_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	int error;
	struct ebpf_dev_ctx *edc;

	error = ebpf_dev_ctx_create(&edc);
	if (error)
		return (error);

	error = devfs_set_cdevpriv(edc, ebpf_dev_ctx_dtor);
	if (error) {
		ebpf_dev_ctx_destroy(edc);
		return (error);
	}

	return (0);
}

static struct cdev *ebpf_dev;
static struct cdevsw ebpf_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "ebpf",
	.d_open = ebpf_open,
	.d_ioctl = ebpf_ioctl
};

const static struct ebpf_config ec_kernel = {
	.prog_types = {
		[EBPF_PROG_TYPE_UNSPEC] = NULL
	},
	.map_types = {
		[EBPF_MAP_TYPE_UNSPEC] = NULL,
		[EBPF_MAP_TYPE_ARRAY] = &emt_array,
		[EBPF_MAP_TYPE_PERCPU_ARRAY] = &emt_percpu_array,
		[EBPF_MAP_TYPE_HASH] = &emt_hashtable,
		[EBPF_MAP_TYPE_PERCPU_HASH] = &emt_percpu_hashtable
	},
	.helper_types = {
		[EBPF_HELPER_TYPE_unspec] = NULL,
		[EBPF_HELPER_TYPE_map_lookup_elem] = &eht_map_lookup_elem,
		[EBPF_HELPER_TYPE_map_update_elem] = &eht_map_update_elem,
		[EBPF_HELPER_TYPE_map_delete_elem] = &eht_map_delete_elem
	},
	.preprocessor_type = NULL
};

/*
 * Module operations
 */

static void
init_globals(void)
{
	/* Initialize the global lock */
	EBPF_DEV_GLOBAL_LOCK_INIT();

	/* Initialize the global refcount */
	refcount_init(&ebpf_global_refcount, 1);

	/* Initialize the global environment registry */
	memcpy(ebpf_global_envs, 0,
			sizeof(*ebpf_global_envs) * EBPF_ENV_MAX);

	/* Initialize the eBPF object file operations */
	memcpy(&ebpf_obj_file_ops, &badfileops, sizeof(ebpf_obj_file_ops));
	ebpf_obj_file_ops.fo_close = ebpf_obj_file_close;
}

static int
create_cdev(void)
{
	ebpf_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD, &ebpf_cdevsw,
			0, NULL, UID_ROOT, GID_WHEEL, 0600, "ebpf");
	if (ebpf_dev == NULL) {
		return (EINVAL);
	}

	return 0;
}

static void
destroy_cdev(void)
{
	destroy_dev(ebpf_dev);
}

static int
register_envs(void)
{
	int error;
	struct ebpf_env *ee_kernel;

	/*
	 * Register kernel environment
	 */
	error = ebpf_env_create(&ee_kernel, &ec_kernel);
	if (error != 0)
		return (error);

	error = ebpf_env_register(EBPF_ENV_KERNEL, ee_kernel);
	if (error != 0)
		goto err0;

	return (error);

err0:
	ebpf_env_destroy(ee_kernel);
	return (error);
}

static void
unregister_envs(void)
{
	int error;
	struct ebpf_env *ee;

	ee = ebpf_env_unregister(EBPF_ENV_KERNEL);
	KASSERT(ee != NULL, "Failed to unregister kernel environment");

	error = ebpf_env_destroy(ee);
	KASSERT(error != 0, "Failed to destroy kernel environment");
}

static void
start_draining(void)
{
	/*
	 * Shut-out the users by removing the cdev
	 */
	destroy_cdev();

	/*
	 * Unregister all built-in environments
	 */
	unregister_envs();

	/*
	 * Turn on the draining flag
	 */
	EBPF_DEV_GLOBAL_LOCK();
	draining = true;
	EBPF_DEV_GLOBAL_UNLOCK();
}

static int
ebpf_load(void)
{
	int error;

	init_globals();

	error = ebpf_init();
	if (error != 0)
		return error;

	error = register_envs();
	if (error != 0)
		goto err0;

	error = create_cdev();
	if (error != 0)
		goto err1;

	return 0;

err1:
	unregister_envs();
err0:
	KASSERT(ebpf_deinit() == 0, "ebpf_deinit failed");
	return (error);
}

static int
ebpf_unload(void)
{
	EBPF_DEV_GLOBAL_LOCK();

	if (!draining)
		start_draining();

	EBPF_DEV_GLOBAL_UNLOCK();

	return (no_user() ? 0 : EBUSY)
}

static int
ebpf_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error;

	switch (event) {
	case MOD_LOAD:
		error = ebpf_load();
		break;
	case MOD_UNLOAD:
		error = ebpf_unload();
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(ebpf, ebpf_loader, NULL);
MODULE_VERSION(ebpf, 1);
