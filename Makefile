NAME		:= test
obj-m		:= $(NAME).o
# KDIR 		:= /lib/modules/$(shell uname -r)/build
KDIR 		:= /usr/src/linux-headers-4.15.0-30deepin-generic
# KDIR            := /lib/modules/4.19.126/build

$(NAME)-y	:= main.o 

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

test:
	# We put a — in front of the rmmod command to tell make to ignore
	# an error in case the module isn’t loaded.
	- sudo rmmod $(NAME)
	# Clear the kernel log without echo
	sudo dmesg -C
	# Insert the module
	sudo insmod $(NAME).ko

	- sudo chrt -f 99 perf_4.9 stat -r 2500 -d ls > /dev/null
	
	cat /proc/elfguard

	# Remove the module
	sudo rmmod $(NAME)

	# Display the kernel log
	# sudo dmesg
