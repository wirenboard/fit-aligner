#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <libfdt.h>

#define eprintf(args...) fprintf(stderr, args)
#define __stringify(a) __stringify_r(a)
#define __stringify_r(a) #a

#define DEFAULT_ALIGN 512
#define DEFAULT_PROPERTY "data"

static char **nodes_to_align = NULL;
static size_t num_nodes = 0;
static const char *propertyname = DEFAULT_PROPERTY;
static int verbose = 0;

void print_help(const char *argv0)
{
    eprintf("Usage: %s -i input.fit -o output.fit [-a <align_to>] "
            "[-p <property name>] NODE1 ... \n\n", argv0);

    eprintf("\t-i input.fit\n\t\tinput (unaligned) FIT file\n");
    eprintf("\t-o output.fit\n\t\toutput (aligned) FIT file name\n");
    eprintf("\t-a <align_to>\n\t\tvalue to align (default is " __stringify(DEFAULT_ALIGN) " bytes)\n");
    eprintf("\t-p property_name\n\t\tproperty to align in nodes (default is '" DEFAULT_PROPERTY "')\n");
    eprintf("\t-h\tprint that help message and exit\n\n");
}

int mmap_fdt(const char *fname, size_t size_inc,
	     void **blobp, struct stat *sbuf, bool delete_on_error)
{
	void *ptr;
	int fd;

	/* Load FIT blob into memory (we need to write hashes/signatures) */
    fd = open(fname, O_RDONLY);

	if (fd < 0) {
		fprintf(stderr, "Can't open %s: %s\n", fname, strerror(errno));
		goto err;
	}

    if (fstat(fd, sbuf) < 0) {
		fprintf(stderr, "Can't stat %s: %s\n", fname, strerror(errno));
		goto err;
	}

	if (size_inc) {
		sbuf->st_size += size_inc;
		if (ftruncate(fd, sbuf->st_size)) {
			fprintf(stderr, "Can't expand %s: %s\n", fname, strerror(errno));
		    goto err;
		}
	}

	errno = 0;
	ptr = mmap(0, sbuf->st_size, PROT_READ, MAP_SHARED, fd, 0);
	if ((ptr == MAP_FAILED) || (errno != 0)) {
		fprintf(stderr, "Can't read %s: %s\n", fname, strerror(errno));
		goto err;
	}

	/* check if ptr has a valid blob */
	if (fdt_check_header(ptr)) {
		fprintf(stderr, "Invalid FIT blob\n");
		goto err;
	}

	/* expand if needed */
	if (size_inc) {
		int ret;

		ret = fdt_open_into(ptr, ptr, sbuf->st_size);
		if (ret) {
			fprintf(stderr, "Cannot expand FDT: %s\n",
				fdt_strerror(ret));
			goto err;
		}
	}

	*blobp = ptr;
	return fd;
err:
	if (fd >= 0)
		close(fd);
	if (delete_on_error)
		unlink(fname);

	return -1;
}

struct fit_segment {
    int start;
    int len;
    int after_structs;
    fdt32_t *header_piece;
};

int cmp_fit_segments(const void *p1, const void *p2)
{
    const struct fit_segment *pp1 = (const struct fit_segment *) p1;
    const struct fit_segment *pp2 = (const struct fit_segment *) p2;

    return pp1->start - pp2->start;
}

#define CHUNK_SIZE 1024
#define min(a, b) ((a) > (b) ? (b) : (a))
void move_unaligned(const void *blob_ptr, FILE *output, const struct fit_segment *s)
{
    size_t size = s->len;
    size_t offset = s->start;

    while (size > 0) {
        size_t chunk = min(CHUNK_SIZE, size);
        if (fwrite((const char *) blob_ptr + offset, 1, chunk, output) != chunk) {
            eprintf("Error writing output FIT: %s\n", strerror(errno));
            return;
        }

        offset += chunk;
        size -= chunk;
    }
}

void fill_nops_align(FILE *output, size_t len)
{
    size_t i;
    fdt32_t nop = cpu_to_fdt32(FDT_NOP);
    assert(len % sizeof (nop) == 0);

    len /= sizeof(nop);

    for (i = 0; i < len; i++) {
        if (fwrite(&nop, sizeof (nop), 1, output) != 1) {
            eprintf("Error writing output FIT: %s\n", strerror(errno));
            return;
        }
    }
}

int move_segment(const void *blob_ptr, FILE *output, const struct fit_segment *s)
{
    char empty_buffer[8] = { 0 };
    int shift = 0;

    /* but still align it to 8 */
    long pos = ftell(output);
    if (pos % 8 != 0) {
        shift = 8 - (pos % 8);

        if ((size_t) shift != fwrite(empty_buffer, 1, shift, output)) {
            eprintf("Error writing output FIT: %s\n", strerror(errno));
            return 0;
        }
    }

    move_unaligned(blob_ptr, output, s);

    return shift;
}

int cmp_ints(const void *p1, const void *p2)
{
    const int *pp1 = (const int *)p1;
    const int *pp2 = (const int *)p2;

    return *pp1 - *pp2;
}

int align_fit_node(int offset, int align_to)
{
    if ((offset + sizeof(struct fdt_property)) % align_to != 0) {
        return align_to - (offset + sizeof(struct fdt_property)) % align_to;
    }
    return 0;
}

int do_write_structs(void *fit_blob, FILE *output, const struct fit_segment *s,
        const int *offsets, const int *node_offsets, int align_to, int *start_shift)
{
    int delta_size = 0;
    int *aoffsets = (int *) malloc(num_nodes * sizeof (int));
    int *anodeoffsets = (int *) malloc((num_nodes + 1) * sizeof (int));
    unsigned int i;
    int asize = 0;
    struct fit_segment sbuf;

    if (!aoffsets) {
        perror("malloc");
        exit(1);
    }

    if (!anodeoffsets) {
        perror("malloc");
        exit(1);
    }
    /* prepare actual offsets */
    for (i = 0; i < num_nodes; i++) {
        if (offsets[i] >= 0) {
            aoffsets[asize] = offsets[i];
            anodeoffsets[asize++] = node_offsets[i];
        }
    }
    qsort(aoffsets, asize, sizeof (int), cmp_ints);
    qsort(anodeoffsets, asize, sizeof (int), cmp_ints);
    anodeoffsets[asize] = s->len;

    sbuf.start = s->start;
    sbuf.len = anodeoffsets[0];

    /* write first part of section */
    *start_shift = move_segment(fit_blob, output, &sbuf);
    delta_size = *start_shift;

    for (int i = 0; i < asize; i++) {
        sbuf.len = anodeoffsets[i + 1] - anodeoffsets[i];
        sbuf.start = s->start + anodeoffsets[i];

        int align = align_fit_node(aoffsets[i] + delta_size, align_to);
        fill_nops_align(output, align);
        delta_size += align;

        move_unaligned(fit_blob, output, &sbuf);
    }

    free(aoffsets);
    free(anodeoffsets);

    return delta_size;
}

void print_fdt_header(const struct fdt_header *h)
{
    eprintf("FDT header\nMagic: %x\nTotalsize: %u\nStruct offset: %u\n",
            fdt_magic(h),
            fdt_totalsize(h),
            fdt_off_dt_struct(h));
    eprintf("Strings offset: %u\nMem offset: %u\nVersion: %u\n",
            fdt_off_dt_strings(h),
            fdt_off_mem_rsvmap(h),
            fdt_version(h));
    eprintf("Comp ver: %u\nBoot CPUID: %u\nStrings size: %u\nStruct size: %u\n",
            fdt_last_comp_version(h),
            fdt_boot_cpuid_phys(h),
            fdt_size_dt_strings(h),
            fdt_size_dt_struct(h));
}

void do_align(void *fit_blob, FILE *output, int align_to)
{
    int *offsets = (int *) malloc(num_nodes * sizeof (int));
    int *node_offsets = (int *) malloc(num_nodes * sizeof (int));
    unsigned int i;

    if (!offsets) {
        perror("malloc");
        exit(1);
    }

    if (!node_offsets) {
        perror("malloc");
        exit(1);
    }

    /* get required offsets */
    for (i = 0; i < num_nodes; i++) {
        const void *nodep;
        int len;
        node_offsets[i] = fdt_path_offset(fit_blob, nodes_to_align[i]);
        if (node_offsets[i] < 0) {
            eprintf("WWW: Node not found: %s, skipping\n", nodes_to_align[i]);
            offsets[i] = -1;
            continue;
        }
        eprintf("Offset of %s is %u\n", nodes_to_align[i], node_offsets[i]);

        nodep = fdt_getprop(fit_blob, node_offsets[i], propertyname, &len);
        offsets[i] = (const char *) nodep - (const char *) fit_blob - sizeof (struct fdt_property);

        eprintf("\tOffset of prop is %u\n", offsets[i]);
    }

    if (verbose) {
        print_fdt_header((const struct fdt_header *) fit_blob);
    }

    /* read sections info */
    struct fdt_header header_copy;
    header_copy.off_dt_struct = fdt_off_dt_struct(fit_blob);
    header_copy.off_dt_strings = fdt_off_dt_strings(fit_blob);
    header_copy.off_mem_rsvmap = fdt_off_mem_rsvmap(fit_blob);
    header_copy.size_dt_struct = fdt_size_dt_struct(fit_blob);
    header_copy.totalsize = fdt_totalsize(fit_blob);

    /* create segments info */
    struct fit_segment segments[4];

    segments[0].start = 0;
    segments[0].header_piece = NULL;

    segments[1].start = fdt_off_dt_struct(fit_blob);
    segments[1].header_piece = &(header_copy.off_dt_struct);

    segments[2].start = fdt_off_dt_strings(fit_blob);
    segments[2].header_piece = &(header_copy.off_dt_strings);

    segments[3].start = fdt_off_mem_rsvmap(fit_blob);
    segments[3].header_piece = &(header_copy.off_mem_rsvmap);

    /* sort sections by starting point */
    qsort(segments, 4, sizeof (struct fit_segment), cmp_fit_segments);
    assert(segments[0].start == 0);

    /* complete sections */
    for (i = 0; i < 4; i++) {
        if (i < 3) {
            segments[i].len = segments[i+1].start - segments[i].start;
        } else {
            segments[i].len = header_copy.totalsize - segments[i].start;
        }
    }

    /* write sections one after another */
    int add = 0;
    for (i = 0; i < 4; i++) {
        int start_shift = 0;
        if (i > 0) {
            *(segments[i].header_piece) += add;
        }

        if (segments[i].header_piece == &(header_copy.off_dt_struct)) {
            int ssize = do_write_structs(fit_blob, output, &segments[i], offsets, node_offsets, align_to, &start_shift);
            add += ssize;
            header_copy.size_dt_struct += ssize;
        } else {
            start_shift = move_segment(fit_blob, output, &segments[i]);
            if (segments[i].header_piece != NULL)
                *(segments[i].header_piece) += start_shift;
            add += start_shift;
        }
    }
    header_copy.totalsize += add;

    /* rewrite header */
    struct fdt_header new_header;
    memcpy(&new_header, fit_blob, sizeof (struct fdt_header));

    fdt_set_off_dt_struct(&new_header, header_copy.off_dt_struct);
    fdt_set_off_dt_strings(&new_header, header_copy.off_dt_strings);
    fdt_set_off_mem_rsvmap(&new_header, header_copy.off_mem_rsvmap);
    fdt_set_size_dt_struct(&new_header, header_copy.size_dt_struct);
    fdt_set_totalsize(&new_header, header_copy.totalsize);

    if (verbose) {
        print_fdt_header(&new_header);
    }

    fseek(output, 0, SEEK_SET);
    if (fwrite(&new_header, sizeof (new_header), 1, output) != 1) {
        eprintf("Failed to rewrite header of new FIT file: %s\n", strerror(errno));
        exit(1);
    }

    fseek(output, 0, SEEK_END);

    free(offsets);
    free(node_offsets);
}

int main(int argc, char *argv[])
{
    const char *input_file = NULL, *output_file = NULL;
    int align_to = DEFAULT_ALIGN;
    void *fit_blob;
    int ffd;
    struct stat fsbuf;
    FILE *output;

    int c;
    while ((c = getopt(argc, argv, "i:o:a:p:hv")) != -1) {
        switch (c) {
        case 'i':
            input_file = optarg;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'a':
            align_to = atoi(optarg);
            break;
        case 'p':
            propertyname = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
        default:
            print_help(argv[0]);
            exit(0);
        }
    }

    /* fill in nodes list */
    nodes_to_align = &argv[optind];
    num_nodes = argc - optind;

    if (num_nodes == 0) {
        eprintf("No nodes to align!\n");
        print_help(argv[0]);
        exit(1);
    }

    if (!input_file) {
        eprintf("No input file!\n");
        print_help(argv[0]);
        exit(1);
    }

    if (!output_file) {
        eprintf("No output file!\n");
        print_help(argv[0]);
        exit(1);
    }

    ffd = mmap_fdt(input_file, 0, &fit_blob, &fsbuf, false);

    if (ffd < 0) {
        eprintf("Can't open %s: %s\n", input_file, strerror(errno));
        exit(1);
    }

    output = fopen(output_file, "wb");
    if (!output) {
        eprintf("Can't open %s for writing: %s\n", output_file, strerror(errno));
        exit(1);
    }

    /* logic here */
    do_align(fit_blob, output, align_to);

    /* append tail */
    size_t tail_len = fsbuf.st_size - fdt_totalsize(fit_blob);
    if (tail_len > 0) {
        if (fwrite((const char *) fit_blob + fdt_totalsize(fit_blob), 1, tail_len, output) != tail_len) {
            eprintf("Failed to append tail to output: %s\n", strerror(errno));
        }
    }

    fclose(output);

    (void) munmap((void *) fit_blob, fsbuf.st_size);
    close(ffd);

    return 0;
}
