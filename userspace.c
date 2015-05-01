#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#define print_value(x) (x==0?"-" : x)
#define NETLINK_USER 31
#define PAYLOAD_SIZE 200

#define RULE_SIZE 200
#define DELETE_SIZE 100
#define PRINT_SIZE 2

struct nlmsghdr *nh = NULL;	//nmlsghdr with payload
struct sockaddr_nl src_addr, dest_addr;
struct iovec iov;
struct msghdr msg;
int sock_fd;

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
static void kernel_comm(char* str, size_t len) {

	sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(sock_fd < 0) {
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; // Linux Kernel pid
	dest_addr.nl_groups = 0;

	nh = (struct nlmsghdr *)malloc(NLMSG_SPACE(PAYLOAD_SIZE));
	memset(nh, 0, NLMSG_SPACE(PAYLOAD_SIZE));
	nh->nlmsg_len = NLMSG_SPACE(PAYLOAD_SIZE);
	nh->nlmsg_pid = getpid();
	nh->nlmsg_flags = 0;

	strncpy(NLMSG_DATA(nh), str, len);
	
	iov.iov_base = (void *)nh;
	iov.iov_len = nh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Sending message to kernel: %s\n", NLMSG_DATA(nh));
	sendmsg(sock_fd, &msg, 0);
	printf("Waiting for message from kernel\n");

	recvmsg(sock_fd, &msg, 0);
	printf("Received message payload: %s\n", NLMSG_DATA(nh));
	close(sock_fd);
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
	printf("send new rule to kernel\n");
	char new_rule[RULE_SIZE];
	printf("%s\n", rule.protocol);

	printf("%s %s %s %s\n", print_value(rule.block_control), print_value(rule.protocol), print_value(rule.port_number), print_value(rule.ip_address));
	//FIGURE THIS OUT FOR RULE SPECIFICS
	sprintf(new_rule, "%s %s %s %s %s\n", "1", print_value(rule.block_control), print_value(rule.protocol), print_value(rule.port_number), print_value(rule.ip_address));

	printf("%s\n", new_rule);

//	kernel_comm(new_rule, RULE_SIZE);
}

void delete_rule_kernel_comm() {
	printf("Send delete rule to kernel\n");
	char *to_delete[DELETE_SIZE];
	sprintf(to_delete, "%s %s\n", "2", print_value(rule_delete.rule_num));
	printf("%s\n", to_delete);

	kernel_comm(to_delete, DELETE_SIZE);
}

//doesn't look like we can do this because there is no file to check the rules
void print_rules() {
	printf("Send print rules to kernel\n");
	char *do_print[PRINT_SIZE];
	sprintf(do_print, "%s\n", "3");
	printf("Print Command: %s\n", do_print);

	kernel_comm(do_print, PRINT_SIZE);
}


int main(int argc, char**argv) {
	char c;
	int command = 1;	// 1-new rule, 2-delete, 3-print

	rule.rule_number = 0;
	rule.block_control = 0;
	rule.port_number = 0;
	rule.ip_address = 0;

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
		printf("%d\n", rule.block_control);
		printf("%s\n", "new command");
		new_rule_kernel_comm();	
	} else if (command == 2) {
		// SEND DELETE RULE TO KERNEL
		printf("%s\n", "delete command");
		delete_rule_kernel_comm();
	} else if (command == 3) {
		// GET PRINT PACKETS FROM KERNEL TO DISPLAY
		printf("%s\n", "print command");
		print_rules();
	}
	
	if (optind < argc) {
		while (optind < argc) {
			putchar('\n');
		}
	}
}
