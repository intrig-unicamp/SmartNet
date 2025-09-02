/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <stdlib.h> 

#include <dpdk_utils.h>


DOCA_LOG_REGISTER(FLOW_RSS_META::MAIN);

/* Sample's Logic */
doca_error_t flow_rss_meta(int nb_queues, const char *src, const char *dst, uint64_t bandwidth, int latency, int jitter, float packet_loss);

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	struct doca_log_backend *sdk_log;
	int exit_status = EXIT_FAILURE;
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 1,
		.port_config.nb_hairpin_q = 1,
		.port_config.enable_mbuf_metadata = 1,
	};

	/* Register a logger backend */
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	/* Register a logger backend for internal SDK errors and warnings */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting the sample");

	result = doca_argp_init("doca_flow_rss_meta", NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}
	doca_argp_set_dpdk_program(dpdk_init);
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

	/* update queues and ports */
	result = dpdk_queues_and_ports_init(&dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update ports and queues");
		goto dpdk_cleanup;
	}

	if(argc < 3){
		DOCA_LOG_ERR("Usage: %s <src> <dst> [other_dpdk_args...]", argv[0]);
    	goto sample_exit;
	}

	const char *src = argv[1];
    const char *dst = argv[2];
	uint64_t bandwidth = strtoull(argv[3], NULL, 10);  // Convert string to uint64_t
	int latency = atoi(argv[4]);                       // Convert string to int
	int jitter = atoi(argv[5]);                        // Convert string to int
	float packet_loss = atof(argv[6]);                 // Convert string to float

	printf("Source: %s\n", src);
    printf("Destination: %s\n", dst);
	printf("Configuration: BW: %lu, Lat: %i, Jit: %i, Loss: %f\n", bandwidth, latency, jitter, packet_loss);

	// Shift argv and argc to skip the first 4 custom args
	argc -= 6;
	argv += 6;

	// Pass the struct to your sample app
	result = flow_rss_meta(dpdk_config.port_config.nb_queues, src, dst, bandwidth, latency, jitter, packet_loss);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("flow_rss_meta() encountered an error: %s", doca_error_get_descr(result));
		goto dpdk_ports_queues_cleanup;
	}

	exit_status = EXIT_SUCCESS;

dpdk_ports_queues_cleanup:
	dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
	dpdk_fini();
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;
}
