# Note: This probably requires GNU Make.

a=$(subst -,- ,$(subst +,+ ,$(1)))
b=$(or $(if $(filter +,$(strip $(1))),$(2) +),$(if $(filter -,$(strip $(1))),$(wordlist 2,$(words $(2)),$(2))),$(if $(filter N,$(strip $(1))),$(2)))
c=$(if $(word 1,$(1)),$(if $(word $(words $(1)),$(2)),$(2),$(2) -),- $(2))
d=$(if $(filter-out -,$(1)),,+)
e=$(call a,$(filter $(subst $(call a) ,,$(strip $(1))$(strip $(2)))%,$(3)))
f=$(wordlist 7,$(words $(1)),$(1))
g=$(call b,$(word 6,$(1)), $(2))
h=$(wordlist 1,$(words $(wordlist 2,$(words $(2)),$(2))),$(3)) $(word 5,$(1)) $(wordlist $(words $(2) -),$(words $(3)),$(3))
i=$(or $(call g,$(1),$(2)),+)
j=$(word $(words $(1)), $(2))
k=$(call l,$(call f, $(1)),$(call i, $(1), $(3)),$(call c,$(call g, $(1), $(3)),$(call h, $(1), $(3), $(4))),$(5))
l=$(if $(call d,$(call m,$(1))),$(words $(filter +,$(3))),$(call k,$(call e, $(call m,$(1)), $(call j,$(2),$(3)),$(4)),$(call m,$(1)),$(2),$(3),$(4)))
m=$(word 1,$(1)) $(or $(word 2,$(1)),+) $(or $(word 3,$(1)),-)

n = +
o = +
p = -
q = ++--+++++ ++-+-+--+ +++---++- ++++-+-++ --+-++-++ --+++++-- -++-+--+- -+++---++ -+--+++-+ -+-++-+++ +-+-++++- +-++++-+- +---++--- +--++-+--
r = [-48, 2, -48, -8, -59, -18, 1, -59, 3, -5, -26, -57, 53, 3, -43, -3, -41, -20, 1, -64, -65, -45, -71, -47, -16, -47, -38, -3, 46, -63, -54, 1, -49, 4, -51, -45, -61, -46, -13, -4, -65, -48, -55, -51, -38, -64, -50, -5, -65, 2, -54, -56, -1, -50, -28]

flag:
	@echo $(call l, $(o), $(n), $(p), $(q)) | sha256sum | python -c "import sys; print ''.join([chr(ord(c) - d) for c,d in zip(sys.stdin.read(),$(r))])" | tee $@
