#ifndef KERNEL_CHEETAH_PLUGIN_H_
#define KERNEL_CHEETAH_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct kernel_cheetah_plugin_t kernel_cheetah_plugin_t;

/**
 * cheetah kernel interface plugin
 */
struct kernel_cheetah_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** KERNEL_CHEETAH_PLUGIN_H_ @}*/
