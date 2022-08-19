#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "drv.h"


static int device_open(struct inode *, struct file *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_release(struct inode *, struct file *f);


static int major_no;

struct vuln_struct {
	unsigned long array[16];
};

// kmalloc-cg-128

#define SLUB_MAXLIST 4096
struct vuln_struct * objlist[SLUB_MAXLIST];
static struct kmem_cache *slubtest_cachep;


static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};

static int device_release(struct inode *i, struct file *f) {
	printk(KERN_INFO "device_release() called\n");
	return 0;
}

static int device_open(struct inode *i, struct file *f) {
	return 0;
}

static DEFINE_MUTEX(objlist_mutex);

static long vuln_alloc(unsigned int index) {

	if(index >= SLUB_MAXLIST)
		return -EFAULT;

	if(objlist[index] != NULL)
		return -EFAULT;

	mutex_lock(&objlist_mutex);
	objlist[index] = kmem_cache_zalloc(slubtest_cachep, GFP_ATOMIC);
	mutex_unlock(&objlist_mutex);

	return index;
}

static long vuln_free(unsigned int index) {

	if(index >= SLUB_MAXLIST)
		return -EFAULT;

	if(objlist[index] == NULL)
		return -EFAULT;

	mutex_lock(&objlist_mutex);
	kmem_cache_free(slubtest_cachep, objlist[index]);
	objlist[index] = NULL;

	mutex_unlock(&objlist_mutex);
	return 0;
}


static long vuln_vulnfunc(unsigned int index) {

        if(index >= SLUB_MAXLIST)
                return -EFAULT;

        if(objlist[index] == NULL)
                return -EFAULT;

        mutex_lock(&objlist_mutex);
	kmem_cache_free(slubtest_cachep, objlist[index]);
	// uaf
        mutex_unlock(&objlist_mutex);
        return 0;
}

static long vuln_read64(struct vuln_input * arg) {
	if(arg->index >= SLUB_MAXLIST)
                return -EFAULT;
	
	if(arg->pos >= 16)
		return -EFAULT;
        if(objlist[arg->index] == NULL)
                return -EFAULT;
	mutex_lock(&objlist_mutex);
	arg->value = objlist[arg->index]->array[arg->pos];
	mutex_unlock(&objlist_mutex);

	return 0;
}


static long vuln_write64(struct vuln_input * arg) {
	if(arg->index >= SLUB_MAXLIST)
		return -EFAULT;
	if(arg->pos >= 16)
		return -EFAULT;
	if(objlist[arg->index] == NULL)
		return -EFAULT;
	mutex_lock(&objlist_mutex);
	objlist[arg->index]->array[arg->pos] = arg->value;
	mutex_unlock(&objlist_mutex);
	return 0;
}

static long vuln_freeall(void) {

	unsigned long i;

	for(i=0; i<SLUB_MAXLIST; i++)
	{
		if(objlist[i] != NULL)
		{
			mutex_lock(&objlist_mutex);
			kmem_cache_free(slubtest_cachep, objlist[i]);
			objlist[i] = NULL;
			mutex_unlock(&objlist_mutex);
		}
	}
	return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {

	struct vuln_input input;

	long res;
	switch(cmd) {
		case IOCTL_ALLOC:
			return vuln_alloc((unsigned int)args);
		case IOCTL_FREE:
			return vuln_free((unsigned int)args);
		case IOCTL_FREEALL:
			return vuln_freeall();
		case IOCTL_READ64:
			if (copy_from_user(&input, (struct vuln_input __user *)args, sizeof(input)))
				return -EFAULT;

			res = vuln_read64(&input);
			
			if(res == 0){
				if (copy_to_user((struct vuln_input __user *)args, &input,sizeof(input)))
					return -EFAULT;
				return 0;
			}

			return res;

		case IOCTL_WRITE64:
                        if (copy_from_user(&input, (struct vuln_input __user *)args, sizeof(input)))
                                return -EFAULT;

			return vuln_write64(&input);
		case IOCTL_VULN:
                        return vuln_vulnfunc((unsigned int)args);
		default:
			break;
	}

	return 0;
}
static struct class *class;

static int __init load(void) {


	memset((void *)objlist, 0, sizeof(objlist));
	printk(KERN_INFO "Driver loaded\n");
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	printk(KERN_INFO "major_no = %d\n", major_no);
	class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(class, NULL, MKDEV(major_no, 0), NULL, DEVICE_NAME);
	slubtest_cachep = kmem_cache_create("slubtest", sizeof(struct vuln_struct), 0, 0, NULL);
	return 0;
}

static void __exit unload(void) {
	vuln_freeall();
	device_destroy(class, MKDEV(major_no, 0));
	class_unregister(class);
	class_destroy(class);
	unregister_chrdev(major_no, DEVICE_NAME);
	kmem_cache_destroy(slubtest_cachep);
	printk(KERN_INFO "Driver unloaded\n");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE("GPL");
