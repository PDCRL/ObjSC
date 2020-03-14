TOPTARGETS := all clean

SUBDIRS = BTO-STM MVTO OSTM MVOSTM Serial Static-Bin Spec-Bin

subdirs:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir; \
	done

