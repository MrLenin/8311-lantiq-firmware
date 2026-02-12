
#define FACTOR_DEFAULT  1.00
#define FACTOR_MIN      0.10
#define FACTOR_MAX      10.0

#define OPTIC_DEVICE_PATH "/dev/optic0"
#define OPTIC_CONFIG_TABLE_PATH "/etc/optic/\0"
#define TABLE_NAME_LENGTH 32
#define MAX_DEPTH 300

#define COMMENT "#"
#define TYPE "Type="

#define TYPE_PTH_CORR        "PTH_CORR"
#define TYPE_LASER_REF       "LASER_REF"
#define TYPE_IBIAS_IMOD      "IBIAS_IMOD"
#define TYPE_MPD_RESP_CORR   "MPD_RESP_CORR"
#define TYPE_TEMP_TRANS      "TEMP_EXT_CORR"
#define TYPE_RSSI_1490_CORR  "RSSI_1490_CORR"
#define TYPE_RSSI_1550_CORR  "RSSI_1550_CORR"
#define TYPE_RF_1550_CORR    "RF_1550_CORR"

#define TCD_MAX            1000
#define TCD_MIN            -1000

#define INTFACTOR_ITH      1000
#define INTFACTOR_SE       1000

#define ACTIVE 1
#define INACTIVE 0

#define OPTIC_EXTRAPOLATION    ACTIVE

struct table_factor
{
	float corr_factor;
	uint8_t quality;
	bool valid;
};

struct table_laserref
{
	float ith;
	float se;
	uint32_t age;
	uint8_t quality;
	bool valid;
};

struct table_ibiasimod
{
	uint16_t ibias[3];
	uint16_t imod[3];
	uint32_t age;
	uint8_t quality;
	bool valid;
};

struct table_vapd
{
	uint16_t vref;
	uint8_t sat;
	uint8_t quality;
	bool valid;
};

struct table_temptrans
{
	uint16_t temp_corr;
	uint8_t quality;
	bool valid;
};

/*
struct temptable
{
	struct pth pth;
	struct laserref laser_ref;
	struct ibiasimod ibias_imod;
};
*/

int optic_cfg(int argc, char *argv[]);
int optic_open(const char *name);
int optic_close(const int fd);
int optic_iocmd(const int fd, const unsigned int cmd, void *data, const unsigned int size);
