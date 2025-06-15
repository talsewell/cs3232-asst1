/* Supplied by UNSW for assignment 1 of the OS course. */
/* Not for broader distribution or re-use. */

#include <types.h>
#include <kern/encoder161.h>
#include <encode_dev.h>
#include <lib.h>
#include <kern/errno.h>
#include <thread.h>


struct encode_device *simulated_encoder;

static char
rot13_code(char x) {
	int v;
	if ('A' <= x && x <= 'Z') {
		v = x - 'A';
		x = 'A';
	}
	else if ('a' <= x && x <= 'z') {
		v = x - 'a';
		x = 'a';
	}
	else {
		return x;
	}
	v = v + 13;
	if (v >= 26) {
		v -= 26;
	}
	return x + ((char) v);
}

static unsigned int
rot13_int_code(unsigned int x) {
	if (x < 256) {
		return rot13_code(x);
	}
	else {
		return x;
	}
}

static unsigned int
shift_code(unsigned int x) {
	x = x ^ (x << 2);
	x = x ^ (x >> 7);
	return x;
}

/* Simulated encode boxes. A future version of the simulator might make these
 * values local to each instance of the simulated device rather than global.
 */
enum {
	NUM_SIM_BOXES = 16,
};
int encode_box_values[NUM_SIM_BOXES];

static unsigned int
box_encode(unsigned int x, struct enc_boxes *boxes) {

	KASSERT(boxes != NULL);
	KASSERT(boxes->box_id1 < NUM_SIM_BOXES);
	KASSERT(boxes->box_id2 < NUM_SIM_BOXES);

	/* This should be a fresh box. */
	if (encode_box_values[boxes->box_id2]) {
		return 0;
	}

	encode_box_values[boxes->box_id2] = x & 15;
	x = x >> 4;

	x = x ^ (encode_box_values[boxes->box_id1] << 24);
	encode_box_values[boxes->box_id1] = 0;

	return x;
}

/* Hint: this operation is an example of concurrency risks. */
static unsigned int
box_flip(unsigned int x, struct enc_boxes *boxes) {

	unsigned int y;

	KASSERT(boxes != NULL);
	KASSERT(boxes->box_id1 < NUM_SIM_BOXES);
	KASSERT(boxes->box_id2 < NUM_SIM_BOXES);

	y = x ^ encode_box_values[boxes->box_id2];

	encode_box_values[boxes->box_id1] = encode_box_values[boxes->box_id1] ^ y;

	thread_yield();
	
	return encode_box_values[boxes->box_id2];
}


static unsigned int
encode_op (int op_num, unsigned int arg, struct enc_boxes *boxes)
{
	switch(op_num) {
		case ENCODE_ROT13:

			KASSERT(boxes == NULL);

			return rot13_int_code(arg);

		case ENCODE_SHIFTS:

			KASSERT(boxes == NULL);

			return shift_code(arg);

		case ENCODE_BOX_OP_1:

			KASSERT(boxes != NULL);
			KASSERT(simulated_encoder != NULL);

			return box_encode(arg, boxes);

		case ENCODE_BOX_OP_2:

			KASSERT(boxes != NULL);
			KASSERT(simulated_encoder != NULL);

			return box_flip(arg, boxes);

		default:

			KASSERT(! "Unreachable: unknown op num.");
	}
	return 0;
}

/* State of the checksum protocol. A future version of the simulator might
 * make these values local to each instance of the simulated device rather
 * than global. */
int checksum_protocol = 0;
int checksum_counter = 0;

const char * ref_string = "Gur dhvpx oebja sbk whzcf bire gur ynml qbt.";

static int
checksum_rot13_step (unsigned int arg)
{
	if (checksum_protocol != 0 && checksum_protocol != CHECKSUM_ROT13) {
		return EBUSY;
	}

	checksum_protocol = CHECKSUM_ROT13;

	if (arg != ((unsigned int) (ref_string[checksum_counter]))) {
		return EINVAL;
	}

	if (ref_string[checksum_counter] != 0) {
		checksum_counter ++;
	}

	return 0;
}

static int
checksum_boxes_step (unsigned int arg)
{
	if (checksum_protocol != 0 && checksum_protocol != CHECKSUM_BOXES) {
		return EBUSY;
	}

	checksum_protocol = CHECKSUM_BOXES;

	if (arg == 0 || arg >= 1000000) {
		return EINVAL;
	}

	if (checksum_counter < NUM_SIM_BOXES) {
		if (encode_box_values[checksum_counter]) {
			return EINVAL;
		}

		checksum_counter += 1;
	}

	return 0;
}

static int
checksum_mystery_step (unsigned int arg)
{
	if (checksum_protocol != 0 && checksum_protocol != CHECKSUM_MYSTERY) {
		return EBUSY;
	}

	checksum_protocol = CHECKSUM_MYSTERY;

	if (arg == ((unsigned int) ('\n'))) {
		checksum_counter ++;
		return 0;
	}

	if (arg < 32 || arg >= 128) {
		return EINVAL;
	}

	return 0;
}

static int
checksum_finalise (void)
{

	switch(checksum_protocol) {
		case CHECKSUM_ROT13:
			if (ref_string[checksum_counter] != 0) {
				return EINVAL;
			}
			return 0;

		case CHECKSUM_BOXES:
			if (checksum_counter != 8) {
				return EINVAL;
			}
			return 0;

		case CHECKSUM_MYSTERY:
			if (checksum_counter == 7) {
				return 0;
			}
			else {
				return EINVAL;
			}
	}

	return EINVAL;
}

static int
checksum_op (int op_num, unsigned int arg)
{
	int result;

	switch(op_num) {

		case CHECKSUM_FINISHED:
			kprintf("Attempting to finalise protocol %d.\n", checksum_protocol);
			result = checksum_finalise();
			if (result) {
				return result;
			}
			kprintf("Checksum completed (protocol %d)!\n", checksum_protocol);
			return 0;

		case CHECKSUM_RESET:
			checksum_protocol = 0;
			checksum_counter = 0;
			return 0;

		case CHECKSUM_ROT13:
			return checksum_rot13_step(arg);

		case CHECKSUM_BOXES:
			return checksum_boxes_step(arg);

		case CHECKSUM_MYSTERY:
			return checksum_mystery_step(arg);
	}
	return EINVAL;
}

static int
op_supported (int op_num)
{
	switch(op_num) {
		case ENCODE_ROT13:
		case ENCODE_SHIFTS:

			return ENCODE_OP_ARG;

		case ENCODE_BOX_OP_1:
		case ENCODE_BOX_OP_2:

			return ENCODE_OP_ARG_BOXES;

		default:

			return ENCODE_OP_NOT_SUPPORTED;
	}
	return 0;
}

struct encode_device *
get_encode_device(void)
{
	struct encode_device *dev;

	if (simulated_encoder != NULL) {
		return simulated_encoder;
	}

	dev = kmalloc(sizeof(struct encode_device));
	if (dev == NULL) {
		return NULL;
	}

	dev->num_enc_boxes = 16;
	dev->op_supported = op_supported;
	dev->encode_op = encode_op;
	dev->checksum_op = checksum_op;

	simulated_encoder = dev;

	return dev; 
}



