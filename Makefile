SUBDIRS = syscall_tracer

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "Building $@"
	cd c/$@ && make
	cp c/$@/tracer build/$@

clean:
	for dir in $(SUBDIRS); do \
		cd c/$$dir && make cleanall; \
	done
	rm -f build/*

