// boostclientcontrol.cpp : Routes udp inputr to the smbclient input and screen output from smbclient to a udp socket
// CommandProcessorGets() Client calls to wait for input
// handle_console_receive_from() displays any output recieved fromn the udp contolled client

//
#include <iostream>
using namespace std;
#include <boost/thread/thread.hpp>
#include "smbclient.hpp"


extern "C" int smbclientmain(int argc, char *argv[]);

//
// async_tcp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>

#include <queue>          // std::queue
using boost::asio::ip::udp;

// Callbacks for smbclient responses to console
typedef void (*termtype)(char *);
extern void terminal_send(char *response);
extern void log_send(char *message);



class SMBCommandProcessor
{
public:
  SMBCommandProcessor(termtype logoutput, termtype termoutput) : logoutput_(logoutput) , termoutput_(termoutput)
  {

  }
  char *PullNextCommandLine(char *to, int max_count)
  {
    while (commandlinequeue.empty())
    {
    cout << "Pull empty " << endl;
     sleep(1);
    }
    strncpy(to,commandlinequeue.front().c_str(), max_count);
    commandlinequeue.pop();
//    cout << "Pull returning: " << to << ":" << endl;
    return  to;
  }


  void CommandExecute(char *command)
  {
    cout << "CommandExecute call termoutput: " << command << std::endl;
//    termoutput_("Termoutput says: Okay running command :");
    commandlinequeue.push(string(command));
    termoutput_(command);
  }

private:
//  void *(logoutput_)(char *);
  termtype logoutput_;
  termtype termoutput_;
  std::queue<string> commandlinequeue;
};

class UDPSMBCommandProcessor
{
public:
  UDPSMBCommandProcessor(boost::asio::io_service& io_service, short port)
    : io_service_(io_service),
      socket_(io_service, udp::endpoint(udp::v4(), port))
  {
      SMBShell_ = new SMBCommandProcessor(terminal_send, log_send);
      socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&UDPSMBCommandProcessor::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
  }

  void handle_receive_from(const boost::system::error_code& error,
      size_t bytes_recvd)
  {


    data_[bytes_recvd] = 0;
    cout << "UDP recieve from recieved: " << bytes_recvd << " data :" << data_ << std::endl;
//    send_cstring("TESTECHO");

    if (!error && bytes_recvd > 0)
    {
     SMBShell_->CommandExecute(data_);
     socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&UDPSMBCommandProcessor::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
     return;
     string CommandString = data_;
     if (CommandString != "")
     {
       string result = "response: netWorkView Executing: " + CommandString +  "\n";
       cout << "netWorkView Executing: " << CommandString << std::endl;
       strcpy(data_, result.c_str());
     if (CommandString == "quit")
     {
      cout << "Net Server quit bye " << endl;
      io_service_.stop();
      return;
     }
     socket_.async_receive_from(
        boost::asio::buffer(data_, max_length), sender_endpoint_,
        boost::bind(&UDPSMBCommandProcessor::handle_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
      }

    }
    else
    {
      socket_.async_receive_from(
          boost::asio::buffer(data_, max_length), sender_endpoint_,
          boost::bind(&UDPSMBCommandProcessor::handle_receive_from, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));
    }
  }
  char *PullNextCommandLine(char *to, int max_count)
  {
     return SMBShell_->PullNextCommandLine(to, max_count);

  }
  void handle_send_to(const boost::system::error_code& error, size_t bytes_sent)
  {
    cout << "yo send to error :" << error.message() << " bytes: " << bytes_sent << endl;
    return;
  }

private:
  boost::asio::io_service& io_service_;
  udp::socket socket_;
  udp::endpoint sender_endpoint_;
  enum { max_length = 1024 };
  char data_[max_length];
  SMBCommandProcessor *SMBShell_;
};

extern "C" void smb_cli_shell(void);
void runsmbclient()
{
  smb_cli_shell();
}


