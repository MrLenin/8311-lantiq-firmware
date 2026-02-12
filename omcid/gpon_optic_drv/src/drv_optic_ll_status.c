/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/** \file
   Device Driver, STATUS Module - Implementation
*/

/** \addtogroup MAPI_REFERENCE_GOI_INTERNAL Optical Interface API Reference - Internal
   @{
*/

/** \defgroup OPTIC_STATUS_INTERNAL STATUS Module - Internal
   @{
*/

#include "drv_optic_ll_status.h"
#include "drv_optic_common.h"
#include "drv_optic_register.h"
#include "drv_optic_reg_status.h"

/**
   Read Fusing information from STATUS.ANALOG.

   Check how GOI fuse parameters shall be handled
   (for each parameter, store in HW registers and/or use as SW parameters)
   If no valid fuse values are stored in the device, default values shall be used.
         If all fuse values are equal to 0000 of FFFF, unfused state is assumed.
             OPTIC_DEFAULT_FUSE_VCALMM20        =  32
             OPTIC_DEFAULT_FUSE_VCALMM100       =  32
             OPTIC_DEFAULT_FUSE_VCALMM400       =  32
             OPTIC_DEFAULT_FUSE_RCALMM          = 128
             OPTIC_DEFAULT_FUSE_DCDC_APD_OFFSET =  32
             OPTIC_DEFAULT_FUSE_DCDC_APD_GAIN   =  32

   \return
   - OPTIC_STATUS_OK - no errors,
   - OPTIC_STATUS_ERR - error occurs
*/
enum optic_errorcode optic_ll_status_fuses_get ( struct optic_fuses *fuses )
{
	uint32_t reg;
	uint8_t temp;
	int8_t itemp;

	reg = status_r32(fuse0);
	if (reg != 0) {
		fuses->vcal_mm20 =  (reg & STATUS_FUSE0_VCALMM20_MASK)
				        >> STATUS_FUSE0_VCALMM20_OFFSET;
		fuses->vcal_mm100 = (reg & STATUS_FUSE0_VCALMM100_MASK)
				        >> STATUS_FUSE0_VCALMM100_OFFSET;
		fuses->vcal_mm400 = (reg & STATUS_FUSE0_VCALMM400_MASK)
				        >> STATUS_FUSE0_VCALMM400_OFFSET;
		fuses->rcal_mm =    (reg & STATUS_FUSE0_RCALMM_MASK)
				        >> STATUS_FUSE0_RCALMM_OFFSET;
	} else {
		fuses->vcal_mm20  = OPTIC_DEFAULT_FUSE_VCALMM20;
		fuses->vcal_mm100 = OPTIC_DEFAULT_FUSE_VCALMM100;
		fuses->vcal_mm400 = OPTIC_DEFAULT_FUSE_VCALMM400;
		fuses->rcal_mm    = OPTIC_DEFAULT_FUSE_RCALMM;
	}

	reg = status_r32(analog);
	if (reg != 0) {

		/* differ between old and new fuse format: A0 = 1
		   means new format */

		fuses->format = ((reg & STATUS_ANALOG_FS_MASK) >>
		     		        STATUS_ANALOG_FS_OFFSET);

		if (fuses->format == 1) {
			fuses->temp_mm = (reg & STATUS_ANALOG_NEW_TEMPMM_MASK)
					     >> STATUS_ANALOG_NEW_TEMPMM_OFFSET;
			fuses->tbgp =    (reg & STATUS_ANALOG_NEW_TBGP_MASK)
					     >> STATUS_ANALOG_NEW_TBGP_OFFSET;
			fuses->vbgp =    (reg & STATUS_ANALOG_VBGP_MASK)
					     >> STATUS_ANALOG_VBGP_OFFSET;
			fuses->irefbgp = (reg & STATUS_ANALOG_IREFBGP_MASK)
					     >> STATUS_ANALOG_IREFBGP_OFFSET;
			fuses->gain_dac_drive = (reg &
					STATUS_ANALOG_NEW_GAINDRIVEDAC_MASK) >>
					STATUS_ANALOG_NEW_GAINDRIVEDAC_OFFSET;
			fuses->gain_dac_bias = (reg &
					STATUS_ANALOG_NEW_GAINBIASDAC_MASK) >>
					STATUS_ANALOG_NEW_GAINBIASDAC_OFFSET;

		} else {
			fuses->temp_mm = (reg & STATUS_ANALOG_TEMPMM_MASK)
					     >> STATUS_ANALOG_TEMPMM_OFFSET;
			fuses->tbgp =    (reg & STATUS_ANALOG_TBGP_MASK)
					     >> STATUS_ANALOG_TBGP_OFFSET;
			fuses->vbgp =    (reg & STATUS_ANALOG_VBGP_MASK)
					     >> STATUS_ANALOG_VBGP_OFFSET;
			fuses->irefbgp = (reg & STATUS_ANALOG_IREFBGP_MASK)
					     >> STATUS_ANALOG_IREFBGP_OFFSET;
			fuses->gain_dac_drive = (reg &
					STATUS_ANALOG_GAINDRIVEDAC_MASK) >>
					STATUS_ANALOG_GAINDRIVEDAC_OFFSET;
			fuses->gain_dac_bias = (reg &
					STATUS_ANALOG_GAINBIASDAC_MASK) >>
					STATUS_ANALOG_GAINBIASDAC_OFFSET;
		}
	} else {
		fuses->temp_mm        = OPTIC_DEFAULT_FUSE_TEMPMM;
		fuses->tbgp           = OPTIC_DEFAULT_FUSE_TBGP;
		fuses->vbgp           = OPTIC_DEFAULT_FUSE_VBGP;
		fuses->irefbgp        = OPTIC_DEFAULT_FUSE_IREFBGP;

		if(is_falcon_chip_a2x()) {
			fuses->gain_dac_drive = OPTIC_DEFAULT_FUSE_GAINDRIVEDAC_A22;
			fuses->gain_dac_bias  = OPTIC_DEFAULT_FUSE_GAINBIASDAC_A22;
		}
		else {
			fuses->gain_dac_drive = OPTIC_DEFAULT_FUSE_GAINDRIVEDAC;
			fuses->gain_dac_bias  = OPTIC_DEFAULT_FUSE_GAINBIASDAC;
		}
	}

	reg = status_r32(fuse1);
	if (reg != 0) {
		if (fuses->format == 1) {
			fuses->offset_dcdc_ddr =
					OPTIC_DEFAULT_FUSE_DCDC_DDR_OFFSET;
			fuses->gain_dcdc_ddr =
					OPTIC_DEFAULT_FUSE_DCDC_DDR_GAIN;

			temp = (reg & STATUS_FUSE1_OFFSET1V0DCDC_MASK) >>
				      STATUS_FUSE1_OFFSET1V0DCDC_OFFSET;

			/* 2-complement */
			temp = (temp << 3);
			itemp = (int8_t) temp;

			fuses->offset_dcdc_core = itemp / 8;

/*
			fuses->gain_dcdc_core = (reg &
					STATUS_FUSE1_GAIN1V0DCDC_MASK) >>
					STATUS_FUSE1_GAIN1V0DCDC_OFFSET;
*/
			fuses->gain_dcdc_core =
					OPTIC_DEFAULT_FUSE_DCDC_1V0_GAIN;

			temp = (reg & STATUS_FUSE1_OFFSETAPDDCDC_NEW_MASK) >>
				      STATUS_FUSE1_OFFSETAPDDCDC_OFFSET;

			/* 2-complement */
			temp = (temp << 3);
			itemp = (int8_t) temp;

			fuses->offset_dcdc_apd = itemp / 8;

		} else {
			fuses->offset_dcdc_ddr = (reg &
					STATUS_FUSE1_OFFSETDDRDCDC_MASK) >>
					STATUS_FUSE1_OFFSETDDRDCDC_OFFSET;
			fuses->gain_dcdc_ddr = (reg &
					STATUS_FUSE1_GAINDDRDCDC_MASK) >>
					STATUS_FUSE1_GAINDDRDCDC_OFFSET;

			fuses->offset_dcdc_core =
					OPTIC_DEFAULT_FUSE_DCDC_1V0_OFFSET;
			fuses->gain_dcdc_core =
					OPTIC_DEFAULT_FUSE_DCDC_1V0_GAIN;

			fuses->offset_dcdc_apd = (reg &
					STATUS_FUSE1_OFFSETAPDDCDC_MASK) >>
					STATUS_FUSE1_OFFSETAPDDCDC_OFFSET;
		}

		fuses->gain_dcdc_apd = (reg &
					STATUS_FUSE1_GAINAPDDCDC_MASK) >>
					STATUS_FUSE1_GAINAPDDCDC_OFFSET;
	} else {
		fuses->offset_dcdc_ddr  = OPTIC_DEFAULT_FUSE_DCDC_DDR_OFFSET;
		fuses->gain_dcdc_ddr    = OPTIC_DEFAULT_FUSE_DCDC_DDR_GAIN;
		fuses->offset_dcdc_core = OPTIC_DEFAULT_FUSE_DCDC_1V0_OFFSET;
		fuses->gain_dcdc_core   = OPTIC_DEFAULT_FUSE_DCDC_1V0_GAIN;
		fuses->offset_dcdc_apd  = OPTIC_DEFAULT_FUSE_DCDC_APD_OFFSET;
		fuses->gain_dcdc_apd    = OPTIC_DEFAULT_FUSE_DCDC_APD_GAIN;
	}

	return OPTIC_STATUS_OK;
}

enum optic_errorcode optic_ll_status_chip_get ( enum optic_chip *chip )
{
	uint32_t reg;
	uint16_t ver;
	enum optic_errorcode ret = OPTIC_STATUS_OK;

	if (chip == NULL)
		return OPTIC_STATUS_ERR;

	reg = status_r32(config);
	ver = 0xA00 + ((((reg & STATUS_CONFIG_SUBVERS_MASK) >>
				STATUS_CONFIG_SUBVERS_OFFSET) >> 2) << 8);
	ver |= ((((reg & STATUS_CONFIG_SUBVERS_MASK) >>
			 STATUS_CONFIG_SUBVERS_OFFSET) & 3) + 1);
	reg = status_r32(chipid);
	ver |= (((reg & STATUS_CHIPID_VERSION_MASK) >>
			STATUS_CHIPID_VERSION_OFFSET) << 4);

	switch (ver) {
#ifdef CONFIG_WITH_FALCON_A1X
	case 0xA11:
		*chip = OPTIC_CHIP_A11;
		break;
	case 0xA12:
		*chip = OPTIC_CHIP_A12;
		break;
#endif
#ifdef CONFIG_WITH_FALCON_A2X
	case 0xA21:
	case 0xA22:
	case 0xA23:
		*chip = OPTIC_CHIP_A21;
		break;
#endif
	default:
		*chip = OPTIC_CHIP_UNKNOWN;
		ret = OPTIC_STATUS_ERR;
		break;
	}
	return ret;
}


/*! @} */
/*! @} */
