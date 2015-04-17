#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define print_value(x) (x==NULL?"-" : x)

// struct for holding rule information
struct firewall_rule {
	int rule_number;	// indicate which rule this is
	int block_control;	// 0 for unblock, 1 for block
	int protocol;		// 0 all, 1 icmp, 6 tcp, 17 udp
	int port_number;	// block this port
	int ip_address;		// block this ip address
//	int src_ip_address;	// This should probably be added
	
	struct firewall_rule* prev_rule;
	struct firewall_rule* next_rule;
} *fw_tail, *fw_head, *fw_current, rule;

static struct firewall_rule_delete {
	char *cmd;
	char *rule_num;
} rule_delete;

// need send to proc funct
void kernel_comm(char *str) {
	
}

// encode command line input for protocol
int get_protocol(char* protocol) {
	if(strcmp(protocol, "ALL") == 0) {
		return 0;
	} else if (strcmp(protocol, "ICMP") == 0) {
		return 1;
	} else if (strcmp(protocol, "TCP") == 0) {
		return 6;
	} else if (strcmp(protocol, "UDP") == 0) {
		return 17;
	}

	return -1;
}
// encode command line input for block control
int get_block_control(char* blockControl) {
	if(strcmp(blockControl, "BLOCK") == 0) {
		return 1;
	} else if (strcmp(blockControl, "UNBLOCK") == 0) {
		return 0;
	}

	return -1;
}

void new_rule_kernel_comm() {
	//printf("send new rule to kernel\n");
	char new_rule[200];
	//FIGURE THIS OUT FOR RULE SPECIFICS
}

void delete_rule_kernel_comm() {

}

//doesn't look like we can do this because there is no file to check the rules
void print_rule() {

}


int main(int argc, char**argv) {
	int c;
	int command = 1;	// 1-new rule, 2-delete, 3-print

	rule.rule_number = NULL;
	rule.block_control = NULL;
	rule.port_number = NULL;
	rule.ip_address = NULL;

	while(1) {
		static struct option long_options[] =
		{
			{"new", no_argument, 0, 'n'},
			{"delete", required_argument, 0, 'd'},
			{"print", no_argument, 0, 'o'},
			{"ip", required_argument, 0, 'i'},
			{"port", required_argument, 0, 'p'},
			{"protocol", required_argument, 0, 'c'},
			{"action", required_argument, 0, 'a'},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "ndo:i:p:c:a:", long_options, &option_index);
		if(c == -1) {
			break;
		}
		
		switch(c) {
			case 'n':
				command = 1;	//new
				break;
			case 'd':
				command = 2;	//delete
				rule_delete.cmd = (char *)long_options[option_index].name;
				rule_delete.rule_num = optarg;
				break;
			case 'o':
				command = 3;	//print
				break;
			case 'i':
				rule.ip_address = optarg;	// ip_address
				break;
			case 'p':
				rule.port_number = optarg;	//port
				break;
			case 'c':
				rule.protocol = optarg;		//protocol
				break;
			case 'a':
				rule.block_control = optarg;	//action
				break;
			case '?':
				break;
			default:
				abort();
		}
		if(c != 0) {
			printf("%s = %s\n", long_options[option_index].name, optarg);
		}
	}
	if(command == 1) {
		//SEND NEW RULE TO KERNEL
		printf("%s\n", "new command");
	} else if (command == 2) {
		// SEND DELETE RULE TO KERNEL
		printf("%s\n", "delete command");
	} else if (command == 3) {
		// GET PRINT PACKETS FROM KERNEL TO DISPLAY
		printf("%s\n", "print command");
	}
	
	if (optind < argc) {
		while (optind < argc) {
			putchar('\n');
		}
	}
}
