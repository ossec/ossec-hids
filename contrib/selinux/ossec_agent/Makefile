# Build the OSSEC agent SELinux module (requires selinux-policy-devel).
AWK ?= awk
NAME = ossec_agent
SHAREDIR ?= /usr/share/selinux/devel

all: $(NAME).pp

$(NAME).pp: $(NAME).te $(NAME).fc $(NAME).if
	@$(MAKE) -f $(SHAREDIR)/Makefile $@

pp-bz2: $(NAME).pp
	bzip2 -c -9 $(NAME).pp > ../$(NAME).pp.bz2

clean:
	rm -f $(NAME).pp $(NAME).fc.tmp $(NAME).if.tmp $(NAME).te.tmp
	rm -rf tmp

.PHONY: all pp-bz2 clean
