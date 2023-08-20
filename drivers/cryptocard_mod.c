#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include<linux/sysfs.h> 
#include<linux/kobject.h> 
#include <linux/err.h>
#include<linux/pci.h>
#include<asm-generic/io.h>
#include<linux/wait.h>
#include<linux/mm_types.h>

#define ID 0x00
#define LIVE_CHECK 0x04
#define KEY 0x08
#define MMIO_LEN 0x0c
#define MMIO_STAT 0x20
#define ISR 0x24
#define IRR 0x60
#define INT_ACK 0x64
#define MMIO_DATA_ADDR 0x80
#define DMA_ADDR 0x90
#define DMA_LEN 0x98
#define DMA_COMM 0xa0
#define UNUSED 0xa8
#define DEVNAME "demo_device"
#define INTR 0
#define DMA 1
#define DMA_MAX_SIZE 8*1024


static int major;
atomic_t device_opened;
static struct class *demo_class;
struct device *demo_device;
u8 *start;
u8 irq_line;
static char *kbuf;
static dma_addr_t handle;
struct device dev_in_pci;
u32 bar;

u8 config[2] = {0, 0};

DECLARE_WAIT_QUEUE_HEAD(wq);

struct data{
	u8 operation;
	u8 isMapped;
	char *str;
};

static const struct pci_device_id crypto_pci_tbl[] = {
	{ PCI_DEVICE(0x1234, 0xdeba)  },
	{0,}
};

MODULE_DEVICE_TABLE(pci, crypto_pci_tbl);

static int crypto_init_module(void);
static void crypto_exit_module(void);
static int crypto_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void crypto_remove(struct pci_dev *pdev);
static irqreturn_t my_irq_handler(int irq,void *dev_id);

static struct pci_driver crypto_driver = {
	.name = "cryptocard_driver",
	.id_table = crypto_pci_tbl,
	.probe = crypto_probe,
	.remove = crypto_remove
};

static irqreturn_t my_irq_handler(int irq,void *dev_id){
	u32 isr;
	u8 *mem = (u8*)dev_id;

	if(mem != start)
		return IRQ_NONE;

	isr = ioread32(start+ISR);
	iowrite32(isr, start+INT_ACK);
	
	if((isr^0x001) == 0 || (isr^0x100) == 0)
		wake_up_interruptible(&wq);

	printk(KERN_INFO " isr = %x id=%x",  isr, ioread32(mem+ID));

	return IRQ_HANDLED;
}

//-------------------------------------------------------------------------
static int my_open(struct inode *inode, struct file *file){
    atomic_inc(&device_opened);
    try_module_get(THIS_MODULE);
    printk(KERN_INFO "Device opened successfully\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file){
    atomic_dec(&device_opened);
    module_put(THIS_MODULE);
    printk(KERN_INFO "Device closed successfully\n");
    return 0;
}

static ssize_t my_read(struct file *filp, char *ubuf, size_t length, loff_t * offset){ 
    char *buff;
    int i;
    buff = (char*)kzalloc(length, GFP_KERNEL);


    printk(KERN_INFO "In read\n");

    if(config[DMA] == 0 && config[INTR] == 0){ 
    	while((ioread32(start+MMIO_STAT) & 0x01)  != 0);
    	
    	for(i = 0; i < length;i++)
	    buff[i] = ioread8(start+i+0xa8);
        printk(KERN_INFO"length = %lx\n",length);
	
        if(copy_to_user(ubuf, buff, length)){
    		kfree(buff);
	        return -EINVAL;
    	}
    }
	
    if(config[DMA] == 0 && config[INTR] == 1){
	    for(i = 0; i < length; i++)
		    buff[i] = ioread8(start+i+0xa8);
	    if(copy_to_user(ubuf, buff, length)){
		    kfree(buff);
		    return -EINVAL;
	    }
    }

    if(config[DMA] == 1){
	    if(config[INTR] == 0)
	    	while((readq(start+DMA_COMM)&0x1) == 1);
	    for(i = 0; i < length; i++)
		    buff[i] = kbuf[i];
	    if(copy_to_user(ubuf, buff, length)){
		    kfree(buff);
		    return -EINVAL;
	    }
    }

    kfree(buff);
    return length;
}

static ssize_t my_write(struct file *filp, const char *buff, size_t len, loff_t * off){
	char *d, *s;
	unsigned char  a, b;
	struct data *p;
	u8 isMapped;
	u16 key;
	u8 command, type, value;
	int i;
	d = kzalloc(sizeof(struct data), GFP_KERNEL);
	if(copy_from_user(d, buff, sizeof(struct data))){
		kfree(d);
		return -EINVAL;
	}
	
	s = kzalloc(len, GFP_KERNEL);
	p = (struct data*)d;
	if(copy_from_user(s, p->str, len)){
		kfree(s);
		return -EINVAL;
	}
	printk(KERN_INFO "In write\n");

	//p = (struct data*)ubuf;
	command = p->operation;
	isMapped = p->isMapped;
	switch(command){
		case 0:
			if(config[DMA] == 0 && config[INTR] == 0){
				if(isMapped == 0){
					iowrite32((u32)len, start+MMIO_LEN);
					iowrite32(0x00, start+MMIO_STAT);
					printk(KERN_INFO "Hello\n");
					for(i = 0 ; i < len; i++)
						iowrite8(p->str[i], start+0xa8+i);
					writeq(0xa8, start+MMIO_DATA_ADDR);
				}

				else{
					iowrite32(0x00, start+MMIO_STAT);
					writeq(0xa8, start+MMIO_DATA_ADDR);
					while((ioread32(start+MMIO_STAT) & 0x01) != 0);
				}
			}

			if(config[DMA] == 0 && config[INTR] == 1){
				if(isMapped == 0){
					iowrite32((u32)len, start+MMIO_LEN);
					iowrite32(0x80, start+MMIO_STAT);
					printk(KERN_INFO "mmio with interrupt");
					for(i = 0; i < len; i++)
						iowrite8(p->str[i], start+0xa8+i);
					writeq(0xa8, start+MMIO_DATA_ADDR);
					wait_event_interruptible(wq,(ioread32(start+MMIO_STAT) & 0x01) == 0);
				}

				else{
					iowrite32(0x80, start+MMIO_STAT);
					writeq(0xa8, start+MMIO_DATA_ADDR);
					wait_event_interruptible(wq,(ioread32(start+MMIO_STAT) & 0x01) == 0);

				}

			}

			if(config[DMA] == 1){
				writeq((u64)handle, start+DMA_ADDR);
				writeq((u64)len, start+DMA_LEN);
				for(i = 0; i < len; i++)
					iowrite8(p->str[i], kbuf+i);
				if(config[INTR] == 0)
					writeq(0x1, start+DMA_COMM);
				else{
					writeq(0x5, start+DMA_COMM);
					wait_event_interruptible(wq, (readq(start+DMA_COMM)&0x1) == 0);
				}
			}
			break;

		case 1:
			if(config[DMA] == 0 && config[INTR] == 0){
				iowrite32((u32)len, start+MMIO_LEN);
				iowrite32(0x02, start+MMIO_STAT);
				for(i = 0; i < len; i++)
					iowrite8(p->str[i], start+0xa8+i);
				writeq(0xa8, start+MMIO_DATA_ADDR);
			}

			if(config[DMA] == 0 && config[INTR] == 1){
				iowrite32((u32)len, start+MMIO_LEN);
				iowrite32(0x82, start+MMIO_STAT);
				printk(KERN_INFO "writing str in device for decryption(mmio w intr)");
				for(i = 0; i < len; i++)
					iowrite8(p->str[i], start+0xa8+i);
				writeq(0xa8, start+MMIO_DATA_ADDR);
				wait_event_interruptible(wq,(ioread32(start+MMIO_STAT)&0x01)==0);
			}

			if(config[DMA] == 1){
                                 writeq((u64)handle, start+DMA_ADDR);
                                 writeq((u64)len, start+DMA_LEN);
                                 for(i = 0; i < len; i++)
                                        iowrite8(p->str[i], kbuf+i);
				 if(config[INTR] == 0)
                                 	writeq(0x3, start+DMA_COMM);
				 else{
					writeq(0x7, start+DMA_COMM);
					wait_event_interruptible(wq, (readq(start+DMA_COMM)&0x1) == 0);
				 }
                         }
			break;

		case 2:
			a = p->str[0];
			b = p->str[1];
			key = (a<<8) | (b);
			printk(KERN_INFO "a = %d, b = %d\n", (int)a, (int)b);
			iowrite16(key, start+KEY);
			//return 2;
			break;

		case 3:
			type = p->str[0];
			value = p->str[1];
			config[type] = value;
			//return 2;
			break;
	}
	kfree(d);
	kfree(s);
	return len;
}

static int my_mmap(struct file *filp, struct vm_area_struct *vma){
	int ret = 0;
	//struct page *page = NULL;
	u32 size = (u32)(vma->vm_end - vma->vm_start);

	printk(KERN_INFO "size = %x", size);

	//page = virt_to_page((unsigned long)start + (vma->vm_pgoff <<PAGE_SHIFT));
	ret = remap_pfn_range(vma, vma->vm_start, bar>>PAGE_SHIFT, 1024*1024, vma->vm_page_prot);

	return ret;
}

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

//-------------------------------------------------------------------------

static struct file_operations fops = {
    .read = my_read,
    .write = my_write,
    .open = my_open,
    .release = my_release,
    .mmap = my_mmap,
};

MODULE_AUTHOR("Crazy Programmer, abc@xyz.com");
MODULE_DESCRIPTION("Crypto Card Driver");
MODULE_LICENSE("GPL v2");

static int __init crypto_init_module(void)
{
	int err,ret;

	ret = pci_register_driver(&crypto_driver);

	//------------------------------------------------
	//-----------------------------------------------

    	major = register_chrdev(0, DEVNAME, &fops);
    	err = major;
    	if (err < 0) {
        	printk(KERN_ALERT "Registering char device failed with %d\n", major);
        	goto error_regdev;
    	}

    	demo_class = class_create(THIS_MODULE, DEVNAME);
    	err = PTR_ERR(demo_class);
    	if (IS_ERR(demo_class))
        	goto error_class;

    	demo_class->devnode = demo_devnode;

    	demo_device = device_create(demo_class, NULL, MKDEV(major, 0), NULL, DEVNAME);
    	err = PTR_ERR(demo_device);
    	if (IS_ERR(demo_device))
        	goto error_device;

    	//d_buf = kzalloc(16, GFP_KERNEL);
    	printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);
    	atomic_set(&device_opened, 0);

    	//creating 
	
	return ret;
	//return 0;

error_device:
	class_destroy(demo_class);	
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        return  err;

	//return ret;
}

module_init(crypto_init_module);

static void __exit crypto_exit_module(void)
{
	free_irq(irq_line, (void *)(start));
	dma_free_coherent(&dev_in_pci, DMA_MAX_SIZE, kbuf, handle);
	pci_unregister_driver(&crypto_driver);
	//kfree(d_buf);
	device_destroy(demo_class, MKDEV(major, 0));
	class_destroy(demo_class);
	unregister_chrdev(major, DEVNAME);

	pr_info("DEVICE DRIVER REMOVE.....Done\n");
}

module_exit(crypto_exit_module);

static int crypto_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{

	int err;
	u32 id;
	//u8 irq_line;
	//u8 irq_pin;


	err = pci_enable_device(pdev);

	if(err)
		return err;

	//pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &irq_line);
	//pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &irq_pin);
	irq_line = pdev->irq;


	bar = pci_resource_start(pdev, 0);
	start = (u8*)pci_ioremap_bar(pdev, 0);
	iowrite32(0x00112233, start+LIVE_CHECK);
	id = ioread32(start+LIVE_CHECK);

	if (request_irq(irq_line, my_irq_handler, IRQF_SHARED, "cryptocard", (void *)(start))) {
		printk(KERN_INFO "my_device: cannot register IRQ ");
                free_irq(irq_line, (void *)(start));
        }
	
	dev_in_pci = pdev->dev;
	kbuf = dma_alloc_coherent(&dev_in_pci, DMA_MAX_SIZE, &handle, GFP_KERNEL);
	
	
	printk(KERN_INFO "Probing.......\n");
	
	printk(KERN_INFO "id =%lx irq_line = %x ",(unsigned long)id, irq_line);
	//iowrite32(0x1, start+IRR);

	return 0;

}

static void crypto_remove(struct pci_dev *pdev)
{

	pci_disable_device(pdev);

}























