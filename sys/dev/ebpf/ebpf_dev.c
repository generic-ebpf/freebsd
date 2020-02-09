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

	refcount_acquire(&ebpf_global_refcount);

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
		refcount_release(&ebpf_global_refcount);
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

/*
 * Module operations
 */

static int
ebpf_load(void)
{
	int error;

	/*
	 * Initialize the eBPF library
	 */
	error = ebpf_init();
	if (error != 0)
		return error;

	/*
	 * Initialize globals
	 */
	EBPF_DEV_GLOBAL_LOCK_INIT();

	refcount_init(&ebpf_global_refcount, 1);

	for (uint32_t i = 0; i < EBPF_ENV_MAX; i++)
		ebpf_global_envs[i] = NULL;

	memcpy(&ebpf_obj_file_ops, &badfileops, sizeof(ebpf_obj_file_ops));
	ebpf_obj_file_ops.fo_close = ebpf_obj_file_close;

	/*
	 * Initialize the character device
	 */
	ebpf_dev = make_dev_credf(MAKEDEV_ETERNAL_KLD, &ebpf_cdevsw,
			0, NULL, UID_ROOT, GID_WHEEL, 0600, "ebpf");
	if (ebpf_dev == NULL) {
		error = ebpf_deinit();
		KASSERT(error == 0, "ebpf_deinit failed");
		return EINVAL;
	}

	return 0;
}

static int
ebpf_unload(void)
{
	int error = 0;

	/*
	 * Shut out the users by deleting the char device
	 */
	if (ebpf_dev != NULL) {
		destroy_dev(ebpf_dev);
		ebpf_dev = NULL;
	}

	/*
	 * Check the reference count of this module. If the users
	 * are left, take a reference again and return EBUSY.
	 */
	if (refcount_release(&ebpf_global_refcount)) {
		for (uint32_t i = 0; i < EBPF_ENV_MAX; i++) {
			if (ebpf_global_envs[i] != NULL)
				ebpf_env_destroy(ebpf_global_envs[i]);
		}
	} else {
		error = EBUSY;
		refcount_acquire(&ebpf_global_refcount);
	}

	return (error);
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
