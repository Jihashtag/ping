# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jbert <jbert@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2015/05/20 13:40:41 by jbert             #+#    #+#              #
#    Updated: 2016/03/27 19:59:52 by jbert            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #


NAME		= ft_ping

FLAG		= -Wall -Werror -Wextra

SRCS		= ping.c

OBJS		= $(SRCS:.c=.o)

.SILENT:

all:	$(NAME)

$(NAME):
	echo "\\033[1;34mGenerating objects... Please wait.\\033[0;39m"
	printf "\\033[40m LOADING..."
	printf "\\033[44m        "
	printf "        "			
	gcc $(FLAG) -c $(SRCS)
	printf "        "
	gcc $(FLAG) -o $(NAME) $(OBJS)
	printf "        "
	printf "\\033[0;39m\n"

clean:
	rm -rf $(OBJS)

fclean: clean
	rm -rf $(NAME)

re: fclean all
