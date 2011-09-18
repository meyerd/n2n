#include "n2n_wire.h"
#include "n2n_transforms.h"
#include "n2n.h"

#ifndef WIN32
#include <sys/time.h>
#endif
#include <time.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char** argv) {
	peer_info_t* testpeers[PEER_HASH_TAB_SIZE];
	struct sglib_hashed_peer_info_t_iterator it;
	peer_info_t *ll;

	sglib_hashed_peer_info_t_init(testpeers);
		
	for(ll=sglib_hashed_peer_info_t_it_init(&it, testpeers); ll!=NULL; ll=sglib_hashed_peer_info_t_it_next(&it)) {
		sglib_hashed_peer_info_t_delete(testpeers, ll);
		free(ll);
	}
	return 0;
}

