TOPTARGETS := all clean

SUBDIRS = 1.Coin 2.Ballot 3.Auction 4.Mix

subdirs:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir; \
	done

