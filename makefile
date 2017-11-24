PROC=aarch64_cryptoextension
include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)aarch64_cryptoextension$(O)     : $(I)idp.hpp aarch64_cryptoextension.cpp
