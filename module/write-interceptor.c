#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tiago Royer");
MODULE_DESCRIPTION("Data collection tool");

static int wi_constructor(struct dm_target *target, unsigned int argc, char **argv) {
    int i;
    printk(KERN_INFO "wi_constructor(%p, %i, {\n", target, argc);
    for(i = 0; i < argc; i++) {
        printk(KERN_INFO "    \"%s\",\n", argv[i]);
    }
    printk(KERN_INFO "});\n");
    return 0;
}

static void wi_destructor(struct dm_target *ti) {
    printk(KERN_INFO "wi_destructor(%p);\n", ti);
}

static int wi_map_function(struct dm_target *ti, struct bio *bio) {
    printk(KERN_INFO "wi_map_function(%p, %p);\n", ti, bio);
    printk(KERN_INFO "bio_op(%p) -> %x\n", bio, bio_op(bio));
    if(bio_op(bio) == REQ_OP_READ) {
        zero_fill_bio(bio);
    }
    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;
}

static struct target_type write_interceptor_target = {
    .name = "wintercept",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = wi_constructor,
    .dtr = wi_destructor,
    .map = wi_map_function,
};

static int __init wi_init(void) {
    int ret;
    printk(KERN_INFO "wi_init();\n");
    ret = dm_register_target(&write_interceptor_target);
    printk(KERN_INFO "wi_init() -> %i\n", ret);
    return ret;
}

static void __exit wi_exit(void) {
    printk(KERN_INFO "wi_exit();\n");
    dm_unregister_target(&write_interceptor_target);
}

module_init(wi_init);
module_exit(wi_exit);
