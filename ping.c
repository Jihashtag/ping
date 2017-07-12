#include <sys/types.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define PAQ_SIZE 56
#define LOCALHOST "10.0.2.15"

typedef struct		s_time
{
	long int	ms;
	long int	fms;
	int		id;
	struct s_time	*next;
}			t_time;

typedef struct		s_glob
{
	__u8		ttl;
	int		paq_size;
	int		pos;
	int		opts;
	int		good;
	int		error;
	struct timeval	first;
	int		time;
	int		count;
	char		*name;
	t_time		*ms;
}			t_glob;

t_glob		g_info = {0, 0, 0, 0, 0, 0, {0, 0}, 0, 0, 0, 0};

char		ft_strcmp(char *s1, char *s2)
{
	unsigned int	i;

	i = 0;
	while (s1[i] && s2[i] == s1[i])
		i++;
	return (s1[i] - s2[i]);
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	register int		sum = 0;
	u_short			answer = 0;
	register u_short	*w = addr;
	register int		nleft = len;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

int	error_p(char *s)
{
	perror(s);
	exit(1);
	return (-1);
}

size_t	ft_strlen(char *s)
{
	size_t	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

void	print_error(char *s)
{
	write(2, s, ft_strlen(s));
	exit(1);
}

void	print_error_2(char *s, char *s2)
{
	write(2, s, ft_strlen(s));
	write(2, s2, ft_strlen(s2));
	write(1, "\n", 1);
	exit(1);
}

int	init_addr(char *av, struct in_addr *addr, struct sockaddr *s_addr)
{
	if (inet_pton(AF_INET, av, addr) <= 0)
		return (-1);
	s_addr->sa_family = AF_INET;
	if (!inet_ntop(AF_INET, addr, s_addr->sa_data, 14))
		return (-1);
	return (socket(AF_INET, SOCK_RAW, IPPROTO_ICMP));
}

void	ft_bzero(void *s, unsigned int size)
{
	unsigned int	i;

	i = 0;
	while (i < size)
	{
		((char *)s)[i] = 0;
		i++;
	}
}

void	init_structs(struct iphdr *ip, struct icmphdr *icmp, struct msghdr *msg, size_t ip_len, size_t icmp_len, struct sockaddr_in *sa)
{
	struct in_addr	localhost;

	inet_pton(AF_INET, LOCALHOST, &localhost);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = ip_len + icmp_len + g_info.paq_size;
	ip->id = getpid();
	ip->ttl = g_info.ttl;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = localhost.s_addr;
	ip->daddr = sa->sin_addr.s_addr;

	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = getpid();
	icmp->un.echo.sequence = 1;

	ip->check = 0;
	icmp->checksum = 0;

	ip->check = in_cksum((unsigned short *)ip, ip_len);
	icmp->checksum = in_cksum((unsigned short *)icmp, icmp_len + g_info.paq_size);

	ft_bzero(msg, sizeof(struct msghdr));
	msg->msg_control = malloc(sizeof(struct cmsghdr));
	if (!(msg->msg_control))
		print_error("Malloc failed\n");
	msg->msg_controllen = 1;
	msg->msg_iov = (struct iovec *)malloc(sizeof(struct iovec));
	if (!(msg->msg_iov))
		print_error("Malloc failed\n");
	msg->msg_iov[0].iov_base = malloc(ip_len + icmp_len + g_info.paq_size);
	if (!(msg->msg_iov[0].iov_base))
		print_error("Malloc failed\n");
	ft_bzero(msg->msg_iov[0].iov_base, ip_len + icmp_len + g_info.paq_size);
	msg->msg_iov[0].iov_len = ip_len + icmp_len + g_info.paq_size;
	msg->msg_iovlen = 1;
}

void	ft_ping(struct sockaddr s_addr, u_char *send_buff, int sock, char **av, \
		struct iphdr *ip, struct icmphdr *icmp, struct msghdr *msg, \
		size_t ip_len, size_t icmp_len, \
		struct sockaddr_in *sa)
{
	static struct timeval		last = {0, 0};
	static struct timeval		now = {0, 0};
	struct icmphdr			*tmp_icmp;
	static int			tmp = 0;
	struct sockaddr_in		from;
	int				ret;
	t_time				*ms;

	gettimeofday(&last, NULL);
	if ((last.tv_sec - now.tv_sec) < 1)
		return ;

	ms = malloc(sizeof(t_time));
	ft_bzero(ms, sizeof(t_time));
	ms->id = icmp->un.echo.sequence;
	ms->next = g_info.ms;
	g_info.ms = ms;

	msg->msg_name = &from;
	ft_bzero(msg->msg_name, sizeof(from));
	msg->msg_namelen = sizeof(from);

	tmp_icmp = (struct icmphdr *)(msg->msg_iov[0].iov_base + ip_len);

	siginterrupt(SIGALRM, 1);
	alarm(g_info.time);

	gettimeofday(&last, NULL);
	ret = sendto(sock, send_buff, ip->tot_len, 0, &s_addr, sizeof(s_addr));
	if (ret <= 0)
		error_p("send");

	ret = 0;
	do
	{
		if (ret != 0 && g_info.opts & 1)
			printf("%lu bytes from %s: icmp_seq=%d ttl=%d type=%u\n", \
					ret - ip_len, inet_ntoa(from.sin_addr), \
					tmp_icmp->un.echo.sequence, \
					((struct iphdr *)msg->msg_iov[0].iov_base)->ttl, tmp_icmp->type);
		ret = recvmsg(sock, msg, 0);
	}
	while (ret > 0 && ((from.sin_addr.s_addr != sa->sin_addr.s_addr && \
					tmp_icmp->type == 0) ||tmp_icmp->type == 8));
	alarm(0);

	gettimeofday(&now, NULL);

	if (ret > 0 && tmp_icmp->type == 0)
		g_info.good++;
	else
		g_info.error++;

	if (tmp == 0 && ret > 0)
		printf("PING %s (%s) %d(%d) bytes of data.\n", \
				av[g_info.pos], s_addr.sa_data, g_info.paq_size, ret), tmp = 1;

	ms->ms = (now.tv_usec - last.tv_usec) / 1000;
	ms->fms = (now.tv_usec - last.tv_usec) - (ms->ms * 1000);
	if (ret < 0)
	{
		if (g_info.opts & 1)
			perror("");
	}
	else if (!ft_strcmp(av[g_info.pos], s_addr.sa_data) && tmp_icmp->type == 0)
		printf("%lu bytes from %s: icmp_seq=%d ttl=%d time=%ld.%.3ld ms\n", \
				ret - ip_len, inet_ntoa(from.sin_addr), \
				tmp_icmp->un.echo.sequence, \
				((struct iphdr *)msg->msg_iov[0].iov_base)->ttl, \
				ms->ms, ms->fms);
	else if (tmp_icmp->type == 0)
		printf("%lu bytes from %s (%s): icmp_seq=%d ttl=%d time=%ld.%.3ld ms\n", \
				ret - ip_len, av[g_info.pos], inet_ntoa(from.sin_addr), \
				tmp_icmp->un.echo.sequence, \
				((struct iphdr *)msg->msg_iov[0].iov_base)->ttl, \
				ms->ms, ms->fms);
	else if (tmp_icmp->type == 3)
		printf("From %s icmp_seq=%d Destination Unreachable\n", \
				inet_ntoa(from.sin_addr), icmp->un.echo.sequence);
	else if (tmp_icmp->type == 4)
		printf("From %s icmp_seq=%d Source Quench\n", \
				inet_ntoa(from.sin_addr), icmp->un.echo.sequence);
	else if (tmp_icmp->type == 5)
		printf("From %s icmp_seq=%d Redirect for Host\n", \
				inet_ntoa(from.sin_addr), icmp->un.echo.sequence);
	else if (tmp_icmp->type == 11)
		printf("From %s icmp_seq=%d Time to live exceeded\n", \
				inet_ntoa(from.sin_addr), icmp->un.echo.sequence);

	if (g_info.count)
		g_info.count--;

	icmp->un.echo.sequence++;
	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, icmp_len + g_info.paq_size);
	ft_bzero(msg->msg_iov[0].iov_base, ip_len + icmp_len + g_info.paq_size);
}

__u8	get_ttl(char *s)
{
	__u8	ret;
	int	i;

	i = 0;
	ret = 0;
	while (s[i] && s[i] != '\n')
	{
		if (s[i] <= '9' && s[i] >= '0')
		{
			ret *= 10;
			ret += s[i] - '0';
		}
		else
			return (64);
		i++;
	}
	return (ret);
}

int	ft_atoi(char *s)
{
	int	ret;
	int	i;

	i = 0;
	ret = 0;
	while (s[i] && s[i] != '\n')
	{
		if (s[i] <= '9' && s[i] >= '0')
		{
			ret *= 10;
			ret += s[i] - '0';
		}
		else
			return (-1);
		i++;
	}
	return (ret);
}

int	get_paq_size(char **av)
{
	int	i;
	int	tmp;

	i = 0;
	while (av[i])
	{
		if (av[i][0] == '-' && av[i][1] == 's')
		{
			tmp = ft_atoi(av[i + 1]);
			return (tmp > 65535 ? -1 : tmp);
		}
		i++;
	}
	return (PAQ_SIZE);
}

void	help()
{
	printf("Usage : sudo ./ft_ping [-hv] [-s packetsize] \n\t[-W timeout] [-c count] destination\n");
	exit(1);
}

void	options(char **av)
{
	int	i;

	i = 1;
	while (av[i])
	{
		if (!g_info.pos && av[i][0] != '-' && ft_strcmp(av[i - 1], "-s"))
			g_info.pos = i;
		else if (av[i][0] == '-' && av[i][1] == 'v')
			g_info.opts |= 1;
		else if (av[i][0] == '-' && av[i][1] == 'W')
		{
			g_info.time = ft_atoi(av[i + 1]);
			if (g_info.time <= 0)
				print_error("ft_ping: bad linger time.");
			i++;
		}
		else if (av[i][0] == '-' && av[i][1] == 'c')
		{
			g_info.opts |= 2;
			g_info.count = ft_atoi(av[i + 1]);
			if (g_info.count <= 0)
				print_error("ft_ping: bad number of packets to transmit.");
			i++;
		}
		else if (ft_strcmp(av[i], "-s") && ft_strcmp(av[i - 1], "-s"))
			help();
		i++;
	}
	if (!g_info.time)
		g_info.time = 1;
	if (!g_info.pos)
		help();
}

void	sort(t_time *to_sort)
{
	long int	tmp;
	int		f;
	t_time		*start;

	if (to_sort->fms == 0 && to_sort->ms == 0)
		to_sort = to_sort->next;
	start = to_sort;
	f = 0;
	while (to_sort)
	{
		if (to_sort->next && \
				(to_sort->next->ms > to_sort->ms || \
				(to_sort->next->ms == to_sort->ms && \
				to_sort->next->fms > to_sort->fms)))
		{
			tmp = to_sort->next->ms;
			to_sort->next->ms = to_sort->ms;
			to_sort->ms = tmp;
			tmp = to_sort->next->fms;
			to_sort->next->fms = to_sort->fms;
			to_sort->fms = tmp;
			f = 1;
		}
		if (f && !to_sort->next)
		{
			to_sort = start;
			f = 0;
		}
		else
			to_sort = to_sort->next;
	}
}

void	sig_end(int i)
{
	int		nb;

	long int	mtot;
	long int	mmax;
	long int	mmin;
	long int	mavg;

	long int	ftot;
	long int	fmax;
	long int	fmin;
	long int	favg;


	long int	mmdev = 0;
	long int	fmdev = 0;
	long int	mmdev2;
	long int	fmdev2;
	int		nmdev;
	int		nmdev2;
	struct timeval	now;

	t_time		*start;
	t_time		*tmp;

	if (i == SIGINT || i == SIGQUIT)
	{
		gettimeofday(&now, NULL);
		if (i == SIGINT)
			printf("--- %s ping statistics ---\n", g_info.name);
		nb = g_info.ms->id;
		if (nb % 2)
		{
			nmdev = (nb / 2) + 1;
			nmdev2 = 0;
		}
		else
		{
			nmdev = nb / 2;
			nmdev2 = (nb / 2) + 1;
		}
		if (g_info.error && i == SIGINT)
			printf("%d packets transmitted, %d received, %+d errors, %d%% packet loss, time %ldms\n",\
					nb, g_info.good, g_info.error, \
					(int)(((float)(nb - g_info.good) / (float)nb) * 100), \
					(now.tv_sec - g_info.first.tv_sec) * 1000), exit(1);
		else if (i == SIGINT)
			printf("%d packets transmitted, %d received, %d%% packet loss, time %ldms\n", \
					nb, g_info.good, (int)(((float)(nb - g_info.good) / (float)nb) * 100), \
					(now.tv_sec - g_info.first.tv_sec) * 1000);
		mtot = 0;
		ftot = 0;
		start = g_info.ms;
		tmp = start;
		sort(start);
		mmax = g_info.ms->ms;
		fmax = g_info.ms->fms;
		while (g_info.ms)
		{
			if (!g_info.ms->next)
			{
				mmin = g_info.ms->ms;
				fmin = g_info.ms->fms;
			}
			if (nmdev == g_info.ms->id)
			{
				mmdev = g_info.ms->ms;
				fmdev = g_info.ms->fms;
			}
			if (nmdev2 == g_info.ms->id)
			{
				mmdev2 = g_info.ms->ms;
				fmdev2 = g_info.ms->fms;
			}
			mtot += g_info.ms->ms;
			ftot += g_info.ms->fms;
			g_info.ms = g_info.ms->next;
		}
		ftot /= nb;
		favg = (mtot * 1000) / nb;
		mtot /= nb;
		favg -= mtot * 1000;
		favg += ftot;
		mavg = favg / 1000;
		mavg += mtot;
		if (nmdev2)
		{
			fmdev = ((mmdev + mmdev2) * 1000) / 2 + (fmdev + fmdev2) / 2;
			mmdev = (mmdev + mmdev2) / 2;
			fmdev -= (mmdev * 1000);
			mmdev += (fmdev / 1000);
		}

		g_info.ms = start;
		t_time	*tmp2;

		tmp2 = NULL;
		while (tmp)
		{
			if (tmp2)
			{
				tmp2->next = malloc(sizeof(t_time));
				tmp2 = tmp2->next;
			}
			else
			{
				tmp2 = malloc(sizeof(t_time));
				start = tmp2;
			}
			if (mmdev > tmp->ms || (mmdev == tmp->ms && fmdev > tmp->fms))
				tmp2->fms = (mmdev - tmp->ms) * 1000 + (fmdev - tmp->fms);
			else
				tmp2->fms = (tmp->ms - mmdev) * 1000 + (tmp->fms - fmdev);
			tmp2->ms = tmp->fms / 1000;
			tmp2->fms -= (tmp->ms * 1000);
			tmp = tmp->next;
		}
		tmp2->next = NULL;
		sort(start);
		while (start)
		{
			if (start->id == nmdev)
			{
				mmdev = start->ms;
				fmdev = start->fms;
			}
			if (start->id == nmdev2)
			{
				mmdev2 = start->ms;
				fmdev2 = start->fms;
			}
			tmp2 = start;
			start = start->next;
			free(tmp2);
		}
		if (nmdev2)
		{
			mmdev = (mmdev + mmdev2) / 2;
			fmdev = (fmdev + fmdev2) / 2;
		}
		if (i == SIGINT)
			printf("rtt min/avg/max/mdev = %ld.%.3ld/%ld.%.3ld/%ld.%.3ld/%ld.%.3ld ms\n", \
					mmin, fmin, mavg, favg, mmax, fmax, mmdev, fmdev), exit(0);
		else
			printf("%d/%d packets, %d%% loss, min/avg/max/mdev = %ld.%.3ld/%ld.%.3ld/%ld.%.3ld/%ld.%.3ld ms\n", \
					nb, g_info.good, (int)(((float)(nb - g_info.good) / (float)nb) * 100), \
					mmin, fmin, mavg, favg, mmax, fmax, mmdev, fmdev);
		signal(SIGQUIT, &sig_end);
	}
}

int		my_ttl()
{
	int			fd;
	int			ret;
	char			buff[4];

	fd = open ("/proc/sys/net/ipv4/ip_default_ttl", O_RDONLY);
	if (fd < 0)
		return (error_p("get_ttl:"));
	if ((ret = read(fd, buff, 3)) < 0)
		return (error_p("get_ttl:"));
	close(fd);
	buff[ret] = '\0';
	g_info.ttl = get_ttl(buff);
	return (1);
}

int		main(int ac, char **av)
{
	struct sockaddr		s_addr;
	struct in_addr		addr;

	struct iphdr		*ip;
	char			*tmp;
	struct icmphdr		*icmp;

	u_char			*send_buff;

	struct msghdr		msg;
	int			sock;
	int			optval;

	size_t			ip_len;
	size_t			icmp_len;

	struct addrinfo		hint;
	struct addrinfo		*ainfo;
	struct addrinfo		*ainfo2;

	struct sockaddr_in	*s_addr_in;

	if (ac < 2)
		return (0);

	if (getuid() != 0 )
		help();

	my_ttl();
	g_info.paq_size = get_paq_size(av);
	if (g_info.paq_size < 0)
		print_error("ft_ping: paquet size too large\n");
	options(av);
	g_info.name = av[g_info.pos];

	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_RAW;
	hint.ai_protocol = IPPROTO_ICMP;
	hint.ai_addrlen = 0;
	hint.ai_addr = NULL;
	hint.ai_canonname = NULL;
	hint.ai_next = NULL;

	if (getaddrinfo(av[g_info.pos], NULL, &hint, &ainfo))
		print_error_2("ft_ping: unknown host ", av[g_info.pos]);

	av[g_info.pos] = ainfo->ai_canonname;
	while (ainfo)
	{
		s_addr_in = (struct sockaddr_in *)ainfo->ai_addr;
		tmp = inet_ntoa(s_addr_in->sin_addr);
		sock = init_addr(tmp, &addr, &s_addr);
		if (sock > 0)
			break ;
		ainfo2 = ainfo;
		ainfo = ainfo->ai_next;
		free(ainfo2);
	}
	if (sock < 0)
		return (error_p("socket"));

	optval = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)))
		return (error_p("setsockopt"));

	ip_len = sizeof(struct iphdr);
	icmp_len = sizeof(struct icmphdr);
	send_buff = (u_char *)malloc(sizeof(char) * (ip_len + icmp_len + g_info.paq_size + 1));
	if (!send_buff)
		print_error("Malloc failed\n");
	ft_bzero(send_buff, ip_len + icmp_len + g_info.paq_size + 1);
	ip = (struct iphdr *)send_buff;
	icmp = (struct icmphdr *)(send_buff + ip_len);

	init_structs(ip, icmp, &msg, ip_len, icmp_len, s_addr_in);

	if (!ft_strcmp(s_addr.sa_data, LOCALHOST) || !ft_strcmp(s_addr.sa_data, "127.0.0.1"))
		ft_bzero(s_addr.sa_data, 14);

	signal(SIGINT, &sig_end);
	signal(SIGQUIT, &sig_end);
	signal(SIGALRM, &sig_end);
	gettimeofday(&(g_info.first), NULL);
	while ((g_info.count && g_info.opts & 2) || (!(g_info.opts & 2) && 1))
	{
		ft_ping(s_addr, send_buff, sock, av, ip, icmp, &msg, ip_len, icmp_len, s_addr_in);
	}
	sig_end(SIGINT);
	return (0);
}
