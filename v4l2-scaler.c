/*
 * Copyright (C) 2019-2020 Paul Kocialkowski <contact@paulk.fr>
 * Copyright (C) 2020 Bootlin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <libudev.h>

#include <linux/videodev2.h>
#include <linux/media.h>

#include <media.h>
#include <v4l2.h>
#include <v4l2-scaler.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

int v4l2_scaler_complete(struct v4l2_scaler *scaler)
{
	if (!scaler)
		return -EINVAL;

	scaler->output_buffers_index++;
	scaler->output_buffers_index %= scaler->output_buffers_count;

	scaler->capture_buffers_index++;
	scaler->capture_buffers_index %= scaler->capture_buffers_count;

	return 0;
}

int v4l2_scaler_prepare(struct v4l2_scaler *scaler)
{
	if (!scaler)
		return -EINVAL;

	return 0;
}

int v4l2_scaler_run(struct v4l2_scaler *scaler)
{
	struct v4l2_scaler_buffer *output_buffer;
	unsigned int output_index;
	struct v4l2_scaler_buffer *capture_buffer;
	unsigned int capture_index;
	struct timeval timeout = { 0, 300000 };
	int ret;

	if (!scaler)
		return -EINVAL;

	output_index = scaler->output_buffers_index;
	output_buffer = &scaler->output_buffers[output_index];

	ret = v4l2_buffer_queue(scaler->video_fd, &output_buffer->buffer);
	if (ret)
		return ret;

	capture_index = scaler->capture_buffers_index;
	capture_buffer = &scaler->capture_buffers[capture_index];

	ret = v4l2_buffer_queue(scaler->video_fd, &capture_buffer->buffer);
	if (ret)
		return ret;

	ret = v4l2_poll(scaler->video_fd, &timeout);
	if (ret <= 0)
		return ret;

	do {
		ret = v4l2_buffer_dequeue(scaler->video_fd,
					  &output_buffer->buffer);
		if (ret && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	do {
		ret = v4l2_buffer_dequeue(scaler->video_fd,
					  &capture_buffer->buffer);
		if (ret && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return 0;
}

int v4l2_scaler_start(struct v4l2_scaler *scaler)
{
	int ret;

	if (!scaler || scaler->started)
		return -EINVAL;

	ret = v4l2_stream_on(scaler->video_fd, scaler->output_type);
	if (ret)
		return ret;

	ret = v4l2_stream_on(scaler->video_fd, scaler->capture_type);
	if (ret)
		return ret;

	scaler->started = true;

	return 0;
}

int v4l2_scaler_stop(struct v4l2_scaler *scaler)
{
	int ret;

	if (!scaler || !scaler->started)
		return -EINVAL;

	ret = v4l2_stream_off(scaler->video_fd, scaler->output_type);
	if (ret)
		return ret;

	ret = v4l2_stream_off(scaler->video_fd, scaler->capture_type);
	if (ret)
		return ret;

	scaler->started = false;

	return 0;
}

int v4l2_scaler_buffer_setup(struct v4l2_scaler_buffer *buffer,
			     unsigned int type, unsigned int index)
{
	struct v4l2_scaler *scaler;
	int ret;

	if (!buffer || !buffer->scaler)
		return -EINVAL;

	scaler = buffer->scaler;

	v4l2_buffer_setup_base(&buffer->buffer, type, scaler->memory, index,
			       buffer->planes, buffer->planes_count);

	ret = v4l2_buffer_query(scaler->video_fd, &buffer->buffer);
	if (ret) {
		fprintf(stderr, "Failed to query buffer\n");
		goto complete;
	}

	if(scaler->memory == V4L2_MEMORY_MMAP) {
		unsigned int i;

		for (i = 0; i < buffer->planes_count; i++) {
			unsigned int offset;
			unsigned int length;

			ret = v4l2_buffer_plane_offset(&buffer->buffer, i,
						       &offset);
			if (ret)
				goto complete;

			ret = v4l2_buffer_plane_length(&buffer->buffer, i,
						       &length);
			if (ret)
				goto complete;

			buffer->mmap_data[i] =
				mmap(NULL, length, PROT_READ | PROT_WRITE,
				     MAP_SHARED, scaler->video_fd, offset);
			if (buffer->mmap_data[i] == MAP_FAILED) {
				ret = -errno;
				goto complete;
			}
		}
	}

	ret = 0;

complete:
	return ret;
}

int v4l2_scaler_buffer_teardown(struct v4l2_scaler_buffer *buffer)
{
	struct v4l2_scaler *scaler;

	if (!buffer || !buffer->scaler)
		return -EINVAL;

	scaler = buffer->scaler;

	if(scaler->memory == V4L2_MEMORY_MMAP) {
		unsigned int i;

		for (i = 0; i < buffer->planes_count; i++) {
			unsigned int length;

			if (!buffer->mmap_data[i] ||
			    buffer->mmap_data[i] == MAP_FAILED)
					continue;

			v4l2_buffer_plane_length(&buffer->buffer, i, &length);
			munmap(buffer->mmap_data[i], length);
		}
	}

	memset(buffer, 0, sizeof(*buffer));

	return 0;
}

int v4l2_scaler_setup_defaults(struct v4l2_scaler *scaler)
{
	int ret;

	if (!scaler)
		return -EINVAL;

	if (scaler->up)
		return -EBUSY;

	ret = v4l2_scaler_setup_src_dimensions(scaler, 1280, 720);
	if (ret)
		return ret;

	ret = v4l2_scaler_setup_dst_dimensions(scaler, 640, 360);
	if (ret)
		return ret;

	ret = v4l2_scaler_setup_format(scaler, V4L2_PIX_FMT_NV12);
	if (ret)
		return ret;

	return 0;
}

int v4l2_scaler_setup_src_dimensions(struct v4l2_scaler *scaler,
				     unsigned int width, unsigned int height)
{
	if (!scaler || !width || !height)
		return -EINVAL;

	if (scaler->up)
		return -EBUSY;

	scaler->setup.src_width = width;
	scaler->setup.src_height = height;

	return 0;
}

int v4l2_scaler_setup_dst_dimensions(struct v4l2_scaler *scaler,
				     unsigned int width, unsigned int height)
{
	if (!scaler || !width || !height)
		return -EINVAL;

	if (scaler->up)
		return -EBUSY;

	scaler->setup.dst_width = width;
	scaler->setup.dst_height = height;

	return 0;
}

int v4l2_scaler_setup_format(struct v4l2_scaler *scaler, uint32_t format)
{
	if (!scaler)
		return -EINVAL;

	if (scaler->up)
		return -EBUSY;

	scaler->setup.format = format;

	return 0;
}

int v4l2_scaler_setup(struct v4l2_scaler *scaler)
{
	unsigned int src_width, src_height;
	unsigned int dst_width, dst_height;
	unsigned int buffers_count;
	uint32_t format;
	unsigned int i;
	int ret;

	if (!scaler || scaler->up)
		return -EINVAL;

	src_width = scaler->setup.src_width;
	src_height = scaler->setup.src_height;
	dst_width = scaler->setup.dst_width;
	dst_height = scaler->setup.dst_height;
	format = scaler->setup.format;

	/* Capture format */

	v4l2_format_setup_pixel(&scaler->capture_format, scaler->capture_type,
				dst_width, dst_height, format);

	ret = v4l2_format_try(scaler->video_fd, &scaler->capture_format);
	if (ret) {
		fprintf(stderr, "Failed to try capture format\n");
		goto complete;
	}

	ret = v4l2_format_set(scaler->video_fd, &scaler->capture_format);
	if (ret) {
		fprintf(stderr, "Failed to set capture format\n");
		goto complete;
	}

	/* Output format */

	v4l2_format_setup_pixel(&scaler->output_format, scaler->output_type,
				src_width, src_height, format);

	ret = v4l2_format_try(scaler->video_fd, &scaler->output_format);
	if (ret) {
		fprintf(stderr, "Failed to try output format\n");
		goto complete;
	}

	ret = v4l2_format_set(scaler->video_fd, &scaler->output_format);
	if (ret) {
		fprintf(stderr, "Failed to set output format\n");
		goto complete;
	}

	/* Capture buffers */

	buffers_count = ARRAY_SIZE(scaler->capture_buffers);

	ret = v4l2_buffers_request(scaler->video_fd, scaler->capture_type,
				   scaler->memory, buffers_count);
	if (ret) {
		fprintf(stderr, "Failed to allocate capture buffers\n");
		goto error;
	}

	for (i = 0; i < buffers_count; i++) {
		struct v4l2_scaler_buffer *buffer = &scaler->capture_buffers[i];

		buffer->scaler = scaler;

		if (v4l2_type_mplane_check(scaler->capture_type))
			buffer->planes_count =
				scaler->capture_format.fmt.pix_mp.num_planes;
		else
			buffer->planes_count = 1;

		ret = v4l2_scaler_buffer_setup(buffer, scaler->capture_type, i);
		if (ret) {
			fprintf(stderr, "Failed to setup capture buffer\n");
			goto error;
		}
	}

	scaler->capture_buffers_count = buffers_count;

	/* Output buffers */

	buffers_count = ARRAY_SIZE(scaler->output_buffers);

	ret = v4l2_buffers_request(scaler->video_fd, scaler->output_type,
				   scaler->memory, buffers_count);
	if (ret) {
		fprintf(stderr, "Failed to allocate output buffers\n");
		goto complete;
	}

	for (i = 0; i < buffers_count; i++) {
		struct v4l2_scaler_buffer *buffer = &scaler->output_buffers[i];

		buffer->scaler = scaler;

		if (v4l2_type_mplane_check(scaler->output_type))
			buffer->planes_count =
				scaler->output_format.fmt.pix_mp.num_planes;
		else
			buffer->planes_count = 1;

		ret = v4l2_scaler_buffer_setup(buffer, scaler->output_type, i);
		if (ret) {
			fprintf(stderr, "Failed to setup output buffer\n");
			goto error;
		}
	}

	scaler->output_buffers_count = buffers_count;

	scaler->up = true;

	ret = 0;
	goto complete;

error:
	buffers_count = ARRAY_SIZE(scaler->output_buffers);

	for (i = 0; i < buffers_count; i++)
		v4l2_scaler_buffer_teardown(&scaler->output_buffers[i]);

	v4l2_buffers_destroy(scaler->video_fd, scaler->output_type,
			     scaler->memory);

	buffers_count = ARRAY_SIZE(scaler->capture_buffers);

	for (i = 0; i < buffers_count; i++)
		v4l2_scaler_buffer_teardown(&scaler->capture_buffers[i]);

	v4l2_buffers_destroy(scaler->video_fd, scaler->capture_type,
			     scaler->memory);

complete:
	return ret;
}

int v4l2_scaler_teardown(struct v4l2_scaler *scaler)
{
	unsigned int buffers_count;
	unsigned int i;

	if (!scaler || !scaler->up)
		return -EINVAL;

	buffers_count = ARRAY_SIZE(scaler->output_buffers);

	for (i = 0; i < buffers_count; i++)
		v4l2_scaler_buffer_teardown(&scaler->output_buffers[i]);

	v4l2_buffers_destroy(scaler->video_fd, scaler->output_type,
			     scaler->memory);

	buffers_count = ARRAY_SIZE(scaler->capture_buffers);

	for (i = 0; i < buffers_count; i++)
		v4l2_scaler_buffer_teardown(&scaler->capture_buffers[i]);

	v4l2_buffers_destroy(scaler->video_fd, scaler->capture_type,
			     scaler->memory);

	scaler->up = false;

	return 0;
}

int v4l2_scaler_probe(struct v4l2_scaler *scaler)
{
	bool check, mplane_check;
	int ret;

	if (!scaler || scaler->video_fd < 0)
		return -EINVAL;

	ret = v4l2_capabilities_probe(scaler->video_fd, &scaler->capabilities,
				      (char *)&scaler->driver,
				      (char *)&scaler->card);
	if (ret) {
		fprintf(stderr, "Failed to probe V4L2 capabilities\n");
		return ret;
	}

	printf("Probed driver %s card %s\n", scaler->driver, scaler->card);

	mplane_check = v4l2_capabilities_check(scaler->capabilities,
					       V4L2_CAP_VIDEO_M2M_MPLANE);
	check = v4l2_capabilities_check(scaler->capabilities,
					V4L2_CAP_VIDEO_M2M);
	if (mplane_check) {
		scaler->output_type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
		scaler->capture_type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	} else if (check) {
		scaler->output_type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
		scaler->capture_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	} else {
		fprintf(stderr, "Missing V4L2 M2M support\n");
		return -1;
	}

	ret = v4l2_buffers_capabilities_probe(scaler->video_fd,
					      scaler->output_type,
					      &scaler->output_capabilities);
	if (ret)
		return ret;

	ret = v4l2_buffers_capabilities_probe(scaler->video_fd,
					      scaler->capture_type,
					      &scaler->capture_capabilities);
	if (ret)
		return ret;

	scaler->memory = V4L2_MEMORY_MMAP;

	check = v4l2_pixel_format_check(scaler->video_fd, scaler->output_type,
					V4L2_PIX_FMT_NV12);
	if (!check) {
		fprintf(stderr, "Missing NV12 pixel format capture support\n");
		return -EINVAL;
	}

	check = v4l2_pixel_format_check(scaler->video_fd, scaler->capture_type,
					V4L2_PIX_FMT_NV12);
	if (!check) {
		fprintf(stderr, "Missing NV12 pixel format output support\n");
		return -EINVAL;
	}

	return 0;
}

static int media_device_probe(struct v4l2_scaler *scaler, struct udev *udev,
			      struct udev_device *device)
{
	const char *path = udev_device_get_devnode(device);
	struct media_device_info device_info = { 0 };
	struct media_v2_topology topology = { 0 };
	struct media_v2_interface *interfaces = NULL;
	struct media_v2_entity *entities = NULL;
	struct media_v2_pad *pads = NULL;
	struct media_v2_link *links = NULL;
	struct media_v2_entity *scaler_entity;
	struct media_v2_interface *scaler_interface;
	struct media_v2_pad *sink_pad;
	struct media_v2_link *sink_link;
	struct media_v2_pad *source_pad;
	struct media_v2_link *source_link;
	int media_fd = -1;
	int video_fd = -1;
	dev_t devnum;
	int ret;

	media_fd = open(path, O_RDWR);
	if (media_fd < 0)
		return -errno;

	ret = media_device_info(media_fd, &device_info);
	if (ret)
		goto error;

	ret = media_topology_get(media_fd, &topology);
	if (ret)
		goto error;

	if (!topology.num_interfaces || !topology.num_entities ||
	    !topology.num_pads || !topology.num_links) {
		ret = -ENODEV;
		goto error;
	}

	interfaces = calloc(1, topology.num_interfaces * sizeof(*interfaces));
	if (!interfaces) {
		ret = -ENOMEM;
		goto error;
	}

	topology.ptr_interfaces = (__u64)interfaces;

	entities = calloc(1, topology.num_entities * sizeof(*entities));
	if (!entities) {
		ret = -ENOMEM;
		goto error;
	}

	topology.ptr_entities = (__u64)entities;

	pads = calloc(1, topology.num_pads * sizeof(*pads));
	if (!pads) {
		ret = -ENOMEM;
		goto error;
	}

	topology.ptr_pads = (__u64)pads;

	links = calloc(1, topology.num_links * sizeof(*links));
	if (!links) {
		ret = -ENOMEM;
		goto error;
	}

	topology.ptr_links = (__u64)links;

	ret = media_topology_get(media_fd, &topology);
	if (ret)
		goto error;

	scaler_entity = media_topology_entity_find_by_function(&topology,
							       MEDIA_ENT_F_PROC_VIDEO_SCALER);
	if (!scaler_entity) {
		ret = -ENODEV;
		goto error;
	}

	sink_pad = media_topology_pad_find_by_entity(&topology,
						     scaler_entity->id,
						     MEDIA_PAD_FL_SINK);
	if (!sink_pad) {
		ret = -ENODEV;
		goto error;
	}

	sink_link = media_topology_link_find_by_pad(&topology, sink_pad->id,
						    sink_pad->flags);
	if (!sink_link) {
		ret = -ENODEV;
		goto error;
	}

	source_pad = media_topology_pad_find_by_id(&topology,
						   sink_link->source_id);
	if (!source_pad) {
		ret = -ENODEV;
		goto error;
	}

	source_link = media_topology_link_find_by_entity(&topology,
							 source_pad->entity_id,
							 MEDIA_PAD_FL_SINK);
	if (!source_link) {
		ret = -ENODEV;
		goto error;
	}

	scaler_interface = media_topology_interface_find_by_id(&topology,
							       source_link->source_id);
	if (!scaler_interface) {
		ret = -ENODEV;
		goto error;
	}

	devnum = makedev(scaler_interface->devnode.major,
			 scaler_interface->devnode.minor);

	device = udev_device_new_from_devnum(udev, 'c', devnum);
	if (!device) {
		ret = -ENODEV;
		goto error;
	}

	path = udev_device_get_devnode(device);

	video_fd = open(path, O_RDWR | O_NONBLOCK);
	if (video_fd < 0) {
		ret = -errno;
		goto error;
	}

	scaler->media_fd = media_fd;
	scaler->video_fd = video_fd;

	ret = 0;
	goto complete;

error:
	if (media_fd >= 0)
		close(media_fd);

	if (video_fd >= 0)
		close(video_fd);

complete:
	if (links)
		free(links);

	if (pads)
		free(pads);

	if (entities)
		free(entities);

	if (interfaces)
		free(interfaces);

	return ret;
}

int v4l2_scaler_open(struct v4l2_scaler *scaler)
{
	struct udev *udev = NULL;
	struct udev_enumerate *enumerate = NULL;
	struct udev_list_entry *devices;
	struct udev_list_entry *entry;
	int ret;

	if (!scaler)
		return -EINVAL;

	scaler->media_fd = -1;
	scaler->video_fd = -1;

	udev = udev_new();
	if (!udev)
		goto error;

	enumerate = udev_enumerate_new(udev);
	if (!enumerate)
		goto error;

	udev_enumerate_add_match_subsystem(enumerate, "media");
	udev_enumerate_scan_devices(enumerate);

	devices = udev_enumerate_get_list_entry(enumerate);

	udev_list_entry_foreach(entry, devices) {
		struct udev_device *device;
		const char *path;

		path = udev_list_entry_get_name(entry);
		if (!path)
			continue;

		device = udev_device_new_from_syspath(udev, path);
		if (!device)
			continue;

		ret = media_device_probe(scaler, udev, device);

		udev_device_unref(device);

		if (!ret)
			break;
	}

	if (scaler->media_fd < 0) {
		fprintf(stderr, "Failed to open scaler media device\n");
		goto error;
	}

	if (scaler->video_fd < 0) {
		fprintf(stderr, "Failed to open scaler video device\n");
		goto error;
	}

	ret = 0;
	goto complete;

error:
	if (scaler->media_fd) {
		close(scaler->media_fd);
		scaler->media_fd = -1;
	}

	if (scaler->video_fd) {
		close(scaler->video_fd);
		scaler->video_fd = -1;
	}

	ret = -1;

complete:
	if (enumerate)
		udev_enumerate_unref(enumerate);

	if (udev)
		udev_unref(udev);

	return ret;
}

void v4l2_scaler_close(struct v4l2_scaler *scaler)
{
	if (!scaler)
		return;

	if (scaler->media_fd > 0) {
		close(scaler->media_fd);
		scaler->media_fd = -1;
	}

	if (scaler->video_fd > 0) {
		close(scaler->video_fd);
		scaler->video_fd = -1;
	}
}
