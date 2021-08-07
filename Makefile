BASE_DIR = .
SRC = $(BASE_DIR)/encrypt/aka.cpp \
	  $(BASE_DIR)/encrypt/base64.cpp \
	  $(BASE_DIR)/encrypt/md5.cpp \
	  $(BASE_DIR)/encrypt/hex.cpp \
	  $(BASE_DIR)/digest.cpp \
	  $(BASE_DIR)/auth.cpp \

CSRC = $(BASE_DIR)/main.c \
	   $(BASE_DIR)/encrypt/mem_clr.c \
	   $(BASE_DIR)/encrypt/sha256.c \
	   $(BASE_DIR)/encrypt/sha512.c \


INC = -I $(BASE_DIR) 	\
      -I $(BASE_DIR)/encrypt/ \

TAR = AKA.out
LIBTAR = AKA.so

CC = g++
AR = ar
DEBUG = -g

ifdef LIB
CSEL = -fpic -DLIB
LSEL = -shared -o $(LIBTAR)
OBJDIR = build/sobj/
else
LSEL = -o $(TAR)
OBJDIR = build/obj/
endif

OBJ = $(SRC:%.cpp=$(OBJDIR)%.o) 
COBJ = $(CSRC:%.c=$(OBJDIR)%.co) 

all:$(OBJ) $(COBJ)
	echo $(CC) $(DEBUG) $(COBJ) $(OBJ) $(LSEL)
	$(CC) $(DEBUG) $(COBJ) $(OBJ) $(LSEL)

$(OBJ): $(OBJDIR)%.o:%.cpp
	@mkdir -p $(dir $@)
	$(CC) $(CSEL) $(INC) $(DEBUG) -c -o $@ $< 

$(COBJ): $(OBJDIR)%.co:%.c
	@mkdir -p $(dir $@)
	$(CC) $(CSEL) $(INC) $(DEBUG) -c -o $@ $< 

clean:
	rm $(OBJ) $(COBJ) $(TAR) $(LIBTAR)
