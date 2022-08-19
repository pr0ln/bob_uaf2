#define DEVICE_NAME "bob_uaf"
#define DEVICE_PATH "/dev/bob_uaf"



struct vuln_input{
	unsigned int index;
	unsigned int pos;
	unsigned long value;
};

#define IOCTL_SLUBTEST 100
#define IOCTL_ALLOC    _IOW(IOCTL_SLUBTEST, 0, unsigned int)
#define IOCTL_FREE _IOW(IOCTL_SLUBTEST, 1, unsigned int)
#define IOCTL_FREEALL _IO(IOCTL_SLUBTEST, 2)
#define IOCTL_READ64 _IOWR(IOCTL_SLUBTEST, 3, struct vuln_input)
#define IOCTL_WRITE64 _IOW(IOCTL_SLUBTEST, 4, struct vuln_input)
#define IOCTL_VULN _IOW(IOCTL_SLUBTEST, 5, unsigned int)
