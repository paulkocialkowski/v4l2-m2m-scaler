#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/videodev2.h>
#include <linux/media.h>

#include <v4l2.h>
#include <v4l2-scaler.h>

int main(int argc, char *argv[])
{
	struct v4l2_scaler *scaler = NULL;
	unsigned int width = 640;
	unsigned int height = 480;
	unsigned int frames = 10;
	int ret;

	scaler = calloc(1, sizeof(*scaler));
	if (!scaler)
		goto error;

	ret = v4l2_scaler_open(scaler);
	if (ret)
		goto error;

	ret = v4l2_scaler_probe(scaler);
	if (ret)
		goto error;

	ret = v4l2_scaler_setup_defaults(scaler);
	if (ret)
		goto error;

	ret = v4l2_scaler_setup_dst_dimensions(scaler, width, height);
	if (ret)
		return ret;

	ret = v4l2_scaler_setup(scaler);
	if (ret)
		goto error;

	ret = v4l2_scaler_start(scaler);
	if (ret)
		goto error;

	while (frames--) {
		ret = v4l2_scaler_prepare(scaler);
		if (ret)
			goto error;

		ret = v4l2_scaler_run(scaler);
		if (ret)
			goto error;

		ret = v4l2_scaler_complete(scaler);
		if (ret)
			goto error;
	}

	ret = 0;
	goto complete;

error:
	ret = 1;

complete:
	if (scaler) {
		v4l2_scaler_stop(scaler);
		v4l2_scaler_teardown(scaler);
		v4l2_scaler_close(scaler);

		free(scaler);
	}

	return ret;
}
