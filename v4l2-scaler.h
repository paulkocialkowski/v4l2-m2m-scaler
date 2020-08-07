/*
 * Copyright (C) 2019-2020 Paul Kocialkowski <contact@paulk.fr>
 * Copyright (C) 2020 Bootlin
 */

#ifndef _V4L2_SCALER_H_
#define _V4L2_SCALER_H_

#include <linux/videodev2.h>

struct v4l2_scaler;

struct v4l2_scaler_buffer {
	struct v4l2_scaler *scaler;

	struct v4l2_buffer buffer;

	struct v4l2_plane planes[4];
	void *mmap_data[4];
	unsigned int planes_count;
};

struct v4l2_scaler_setup {
	/* Dimensions */
	unsigned int src_width;
	unsigned int src_height;
	unsigned int dst_width;
	unsigned int dst_height;

	/* Format */
	uint32_t format;
};

struct v4l2_scaler {
	int video_fd;
	int media_fd;

	char driver[32];
	char card[32];

	unsigned int capabilities;
	unsigned int memory;

	bool up;
	bool started;

	struct v4l2_scaler_setup setup;

	unsigned int output_type;
	unsigned int output_capabilities;
	struct v4l2_format output_format;
	struct v4l2_scaler_buffer output_buffers[2];
	unsigned int output_buffers_count;
	unsigned int output_buffers_index;

	unsigned int capture_type;
	unsigned int capture_capabilities;
	struct v4l2_format capture_format;
	struct v4l2_scaler_buffer capture_buffers[2];
	unsigned int capture_buffers_count;
	unsigned int capture_buffers_index;

	void *private;
};

int v4l2_scaler_prepare(struct v4l2_scaler *scaler);
int v4l2_scaler_complete(struct v4l2_scaler *scaler);
int v4l2_scaler_run(struct v4l2_scaler *scaler);
int v4l2_scaler_start(struct v4l2_scaler *scaler);
int v4l2_scaler_stop(struct v4l2_scaler *scaler);
int v4l2_scaler_setup_defaults(struct v4l2_scaler *scaler);
int v4l2_scaler_setup_src_dimensions(struct v4l2_scaler *scaler,
				     unsigned int width, unsigned int height);
int v4l2_scaler_setup_dst_dimensions(struct v4l2_scaler *scaler,
				     unsigned int width, unsigned int height);
int v4l2_scaler_setup_format(struct v4l2_scaler *scaler, uint32_t format);
int v4l2_scaler_setup(struct v4l2_scaler *scaler);
int v4l2_scaler_teardown(struct v4l2_scaler *scaler);
int v4l2_scaler_probe(struct v4l2_scaler *scaler);
int v4l2_scaler_open(struct v4l2_scaler *scaler);
void v4l2_scaler_close(struct v4l2_scaler *scaler);

#endif
