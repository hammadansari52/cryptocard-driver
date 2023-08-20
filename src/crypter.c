#include<crypter.h>
#include<string.h>
#include<sys/mman.h>


struct data{
	unsigned char operation;
	uint8_t isMapped;
	char *str;
};

/*
 * Encrypt - 0
 * Decrypt - 1
 * Set Key - 2
 * Set Config - 3
 * MMIO w/o intr mapped - 4
 * MMIO w intr mapped - 5
 */

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{	
	DEV_HANDLE dev = 0;
	dev = open("/dev/demo_device", O_RDWR);
	if(dev < 0)
		return ERROR;

	return dev;
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
	close(cdev);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
	int ret;
	struct data d;
	char *start;
	char *curr = (char*)addr;
	int chunk_size = 4096;
	int no_of_chunks = length/chunk_size;
	int last_chunk = length%chunk_size;
	int i;

	if(isMapped == FALSE)
	{


		for(i = 0; i < no_of_chunks; i++){
			d.str = (char*)malloc(chunk_size);
			if(!d.str)
				return ERROR;

			memcpy(d.str, curr, chunk_size);
			d.operation = 0;
			d.isMapped = isMapped;

			ret = write(cdev, (char*)&d, chunk_size);
			free(d.str);
			if(ret == chunk_size)
				ret = read(cdev, curr, chunk_size);

			if(ret != chunk_size)
				return ERROR;

			curr += chunk_size;


		}


		d.str = (char*)malloc(last_chunk);

		if(!d.str)
			return ERROR;

		memcpy(d.str, curr, last_chunk);
		d.operation = 0;
		d.isMapped = isMapped;
		
		//printf("String len = %d, len(d) = %d", length, sizeof(d));
		ret = write(cdev, (char*)&d, last_chunk);
		free(d.str);
		if(ret == last_chunk)
			ret = read(cdev, curr, last_chunk);
		if(ret == last_chunk)
			return 0;
	}

	if(isMapped == TRUE)
	{
		d.operation = 0;
		d.isMapped = isMapped;
		start = addr-0xa8;
		start[0x0c] = (uint32_t)length;
		ret = write(cdev, (char*)&d, 0);
	}

  return ERROR;
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
        int ret;
        struct data d;
        char *start;
        char *curr = (char*)addr;
        int chunk_size = 4096;
        int no_of_chunks = length/chunk_size;
        int last_chunk = length%chunk_size;
        int i;

        if(isMapped == FALSE)
        {


                for(i = 0; i < no_of_chunks; i++){
                        d.str = (char*)malloc(chunk_size);
                        if(!d.str)
                                return ERROR;

                        memcpy(d.str, curr, chunk_size);
                        d.operation = 1;
                        d.isMapped = isMapped;

                        ret = write(cdev, (char*)&d, chunk_size);
                        free(d.str);
                        if(ret == chunk_size)
                                ret = read(cdev, curr, chunk_size);

                        if(ret != chunk_size)
                                return ERROR;

                        curr += chunk_size;


                }

                d.str = (char*)malloc(last_chunk);

                if(!d.str)
                        return ERROR;

                memcpy(d.str, curr, last_chunk);
                d.operation = 1;






                ret = write(cdev, (char*)&d, last_chunk);
		free(d.str);
                if(ret == last_chunk)
                        ret = read(cdev, curr, last_chunk);
                if(ret == last_chunk)
                        return 0;
        }

  return ERROR;
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
	int ret;
	struct data d;

	d.operation = 2;
	d.str = (char*)malloc(2);
	if(!d.str){
		return ERROR;
	}
	d.str[0] = a;
	d.str[1] = b;

	ret = write(cdev, (char*)&d, 2);
	//free(d.str);
       	if(ret == 2)	
		return 0;	
	return ERROR;

}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
	int ret;
	struct data d;

	d.operation = 3;
	d.str = (char*)malloc(2);
	if(!d.str)
		return ERROR;
	d.str[0] = type;
	d.str[1] = value;


	ret = write(cdev, (char*)&d, 2);
	free(d.str);
	if(ret == 2)
		return 0;

	return ERROR;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
	ADDR_PTR ptr = NULL;
	size += 1;
	if((size+0xa8) > 1024*1024)
		return NULL;
	ptr = mmap(NULL, 1024*1024, PROT_READ|PROT_WRITE, MAP_SHARED, cdev, 0);
  	return ptr+0xa8;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
	munmap(addr, 1024*1024);
}
