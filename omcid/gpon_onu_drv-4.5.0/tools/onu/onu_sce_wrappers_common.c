/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include "onu_sce_wrappers_common.h"

int table_read(int onu_fd, uint32_t id, size_t size, uint32_t instance, uint32_t index, struct gpe_table_entry *entry)
{
	int ret;

	entry->id = id;
	entry->instance = instance;
	entry->index = index;

	ret = onu_iocmd(onu_fd, FIO_GPE_TABLE_ENTRY_READ, entry, size);
	if (ret)
		return ret;

	return 0;
}

void wrapper_begin(enum output_type type, FILE *f, const char *name)
{
	if (type == OUTPUT_XML)
		fprintf(f, "<wrapper name='%s'>\n", name);
	else
		fprintf(f, "{\n\t\"name\" : \"%s\"", name);
}

void wrapper_end(enum output_type type, FILE *f)
{
	if (type == OUTPUT_XML)
		fprintf(f, "</wrapper>\n");
	else
		fprintf(f, "\n}\n");
}

void wrapper_entry_begin(enum output_type type, FILE *f, uint32_t index)
{
	if (type == OUTPUT_XML)
		fprintf(f, "\t<entry index='%u'>\n", index);
	else
		fprintf(f, ",\n\t\"%u\" : {", index);
}

void wrapper_entry_end(enum output_type type, FILE *f)
{
	if (type == OUTPUT_XML)
		fprintf(f, "\t</entry>\n");
	else
		fprintf(f, "\n\t}");
}

void wrapper_field(enum output_type type, FILE *f, bool first, const char *name, const char *value_type, uint32_t value)
{
	if (type == OUTPUT_XML) {
		fprintf(f, "\t\t<field name='%s' type='%s'>0x%x</field>\n", name, value_type, value);
	} else {
		if (!first)
			printf(",");

		fprintf(f, "\n\t\t\"%s\" : {\n\t\t\t\"type\" : \"%s\",\n\t\t\t\"value\" : \"0x%x\"\n\t\t}", name, value_type, value);
	}
}
