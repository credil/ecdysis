MIN_KREL = "2.6.31"
MAX_KREL = "2.6.35"
RPM_NAME=ecdysis-nf-nat64
SRC_REL_NAME=${RPM_NAME}-${VER}

VER=20101117

obj-m += nf_nat64.o

nf_nat64-objs += nf_nat64_main.o nf_nat64_session.o nf_nat64_config.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)


all: checkversion
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

checkversion:
	@(echo ${MIN_KREL}; \
        	 uname -r | sed -r 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/'; \
	         echo ${MAX_KREL}) | sort -c 2>/dev/null; \
	if [[ "$$?" != "0" ]]; then \
	echo '*****************************************************************';\
	echo 'ERROR:  This module is expected to compile on kernel ';\
	echo '		>= ${MIN_KREL} and <= ${MAX_KREL}' ; \
	echo '*****************************************************************';\
	false ;\
	fi

src-pkg:
	git archive HEAD --prefix=${SRC_REL_NAME}/ | gzip -c > ${SRC_REL_NAME}.tar.gz

rpmbuild-req:
	sudo yum install -y --nogpgcheck kernel-devel kernel-headers

rpm: src-pkg rpmbuild-req
	cp ${SRC_REL_NAME}.tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -ba ${RPM_NAME}.spec

