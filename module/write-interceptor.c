#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tiago Royer");
MODULE_DESCRIPTION("Data collection tool");

/* This device mapper will only support reading/writing the entire block device.
 * So, the only context structure needed is a pointer to the underlying device.
 */
struct wi_context {
    struct dm_dev *dev;
};
struct wi_context *new_wi_context(void) {
    return kmalloc(sizeof(struct wi_context), GFP_KERNEL);
}
void delete_wi_context(struct wi_context *context) {
    kfree(context);
}

static int wi_constructor(struct dm_target *ti, unsigned int argc, char **argv) {
    int i;
    int ret = 1;
    struct wi_context *context = NULL;

    printk(KERN_INFO "wi_constructor(%p, %i, {\n", ti, argc);
    for(i = 0; i < argc; i++) {
        printk(KERN_INFO "    \"%s\",\n", argv[i]);
    }
    printk(KERN_INFO "});\n");

    if(argc == 0) {
        ti->error = "Missing device argument";
        goto error;
    }

    context = new_wi_context();
    if(!context) {
        ti->error = "Not enough memory when allocating wi_context";
        goto error;
    }

    ret = dm_get_device(ti, argv[0],
                dm_table_get_mode(ti->table), &context->dev
            );
    if(ret) {
        ti->error = "Error acquiring underlying block device";
        goto error;
    }

    ti->private = context;
    return 0;

error: // TODO: Error handling was not thoroughly tested
    delete_wi_context(context);
    return ret;
}

static void wi_destructor(struct dm_target *ti) {
    struct wi_context *context;
    printk(KERN_INFO "wi_destructor(%p);\n", ti);
    context = ti->private;
    dm_put_device(ti, context->dev);
    delete_wi_context(context);
}

static int wi_map_function(struct dm_target *ti, struct bio *bio) {
    struct wi_context *context;
    printk(KERN_INFO "wi_map_function(%p, %p);\n", ti, bio);
    printk(KERN_INFO "bio_op(%p) -> %x\n", bio, bio_op(bio));


    if(bio_op(bio) == REQ_OP_WRITE) {
        // Inspect the data that's being written
        unsigned long flags;
        struct bio_vec bv;
        struct bvec_iter iter;

        bio_for_each_segment(bv, bio, iter) {
            char *data = bvec_kmap_irq(&bv, &flags);

            char *data_bytes = kmalloc(bv.bv_len * 3 + 1, GFP_KERNEL);
            if(data) {
                int i;
                for(i = 0; i < bv.bv_len; i++) {
                    sprintf(data_bytes + 3*i, "%0x ", data[i]);
                }
                data_bytes[3 * bv.bv_len] = '\0'; // Just in case bv.bv_len == 0
            }
            printk(KERN_INFO " write(%u) %s\n", bv.bv_len, data_bytes? data_bytes : "kmalloc failed");
            kfree(data_bytes);

            bvec_kunmap_irq(data, &flags);
        }
    }

    // Redirect the block IO request to the underlying device
    context = ti->private;
    bio_set_dev(bio, context->dev->bdev);
    bio->bi_iter.bi_sector = 0 /* start */ + dm_target_offset(ti, bio->bi_iter.bi_sector);

    return DM_MAPIO_REMAPPED;
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
