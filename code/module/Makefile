obj-m += write-interceptor.o

all:
	@pwd | grep ' ' && echo Warning: the build directory should not contain spaces!; true
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@pwd | grep ' ' && echo Warning: the build directory should not contain spaces!; true
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
