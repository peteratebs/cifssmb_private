// boostclientconsole.cpp : Starts the client and then handles keyboard input only
// using udp/localhost
// UDPConsoleRun() sends any keyboard input to the udp controlled client for processing
// handle_console_receive_from() displays any output recieved fromn the udp contolled client
#include <iostream>
using namespace std;
#include <boost/thread/thread.hpp>
#include "smbclient.hpp"


extern "C" int smbclientmain(int argc, char *argv[]);


#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>

using boost::asio::ip::udp;

extern "C" void CommandProcessorPuts(char *buffer);

static inline void echo_command(string & s) {CommandProcessorPuts((char *)s.c_str());};



char *boostclientconsole::targetname = (char *)"localhost";
char *boostclientconsole::targetport = (char *)"3200";
int  boostclientconsole::itargetport =  3200;
char *boostclientconsole::targetsinkport = (char *)"3201";
int  boostclientconsole::itargetsinkport =  3201;
   // code declarations

class UDPCommandSource
{
public:
	UDPCommandSource(
		boost::asio::io_service& io_service,
		const std::string& host,
		const std::string& port
	) : io_service_(io_service), socket_(io_service, udp::endpoint(udp::v4(), 0)) {
		udp::resolver resolver(io_service_);
		udp::resolver::query query(udp::v4(), host, port);
		udp::resolver::iterator iter = resolver.resolve(query);
		endpoint_ = *iter;
  }
  void UDPCommandSourceRun()
  {
   std::cout.setf( std::ios_base::unitbuf );
   for(;;)
   {
     string CommandString;
     string s;
     char b[1024];
       cout << "getine called" << endl;
       cin.getline (b,1024);
       cout << "getine bask" << endl;
       s = b;
       if (s.length() == 0)
         s = "\n";
       CommandString = s;
       echo_command(CommandString);
       if (CommandString == "quit")
       {
        cout << "Console quit bye " << endl;
        return;
       }
       io_service_.run_one();
   }
  }

	~UDPCommandSource()
	{
		socket_.close();
	}

	void send(const std::string& msg) {
		socket_.send_to(boost::asio::buffer(msg, msg.size()), endpoint_);
	}

private:
	boost::asio::io_service& io_service_;
	udp::socket socket_;
	udp::endpoint endpoint_;
};

class UDPCommandSink
{
public:
	UDPCommandSink(
		boost::asio::io_service& io_service,
		const std::string& host,
		const std::string& port
	) : io_service_(io_service), socket_(io_service, udp::endpoint(udp::v4(), 0)) {
		udp::resolver resolver(io_service_);
		udp::resolver::query query(udp::v4(), host, port);
		udp::resolver::iterator iter = resolver.resolve(query);
		endpoint_ = *iter;
        socket_.async_receive_from(
          boost::asio::buffer(echodata_, max_length), endpoint_,
          boost::bind(&UDPCommandSink::handle_console_receive_from, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));

	}
  void handle_console_receive_from(const boost::system::error_code& error,  size_t bytes_recvd)
  {
    // Display console replies and refire port listener
    echodata_[bytes_recvd] = 0;
    std::cout << "UDPC: n: " << bytes_recvd << "  UDPC: data:" << echodata_ << ":end:" << std::endl;
    socket_.async_receive_from(
        boost::asio::buffer(echodata_, max_length), endpoint_,
        boost::bind(&UDPCommandSink::handle_console_receive_from, this,
        boost::asio::placeholders::error,
        boost::asio::placeholders::bytes_transferred));
  }
  void UDPCommandSinkRun()
  {
   for(;;)
   {
     cout << "io_service_ called" << endl;
     io_service_.run_one();
   }
  }

	~UDPCommandSink()
	{
		socket_.close();
	}

	void send(const std::string& msg) {
		socket_.send_to(boost::asio::buffer(msg, msg.size()), endpoint_);
	}

private:
	boost::asio::io_service& io_service_;
	udp::socket socket_;
	udp::endpoint endpoint_;
    enum { max_length = 1024 };
    char echodata_[max_length];
};




#if (0)

static void runudpsmbclientsource()
{
  cout << "runudpsmbclientsource command processor is Executing: " << std::endl;

  try
  {
    boost::asio::io_service io_service;
//    UDPSMBCommandProcessor s(io_service, 3200);
//    UDPCommandProcessor = new UDPSMBCommandProcessor(io_service, boostclientconsole::itargetport/*3200*/);
    UDPCommandSource s(io_service, boostclientconsole::itargetport/*3200*/);
    cout << "Running io service" << endl;
    io_service.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }
}

static void runudpsmbclientsink()
{
  cout << "runudpsmbclientsink command processor is Executing: " << std::endl;
  try
  {
    boost::asio::io_service io_frservice;
//    UDPSMBCommandProcessor s(io_service, 3200);
    UDPCommandSink = new UDPSMBCommandSink(io_frservice, boostclientconsole::itargetsinkport/*3200*/);
    cout << "Running io service for sink" << endl;
    io_frservice.run();
    cout << endl << "io service finished" << endl;
    delete UDPCommandSink;
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }
}

#endif

extern void runsmbclient();

int boostmain(int argc, char* argv[])
{
  runsmbclient();
  return 0;
#if(0)
  boost::thread udpsmbclientSourceThread(runudpsmbclientsource);
  boost::thread udpsmbclientSinkThread(runudpsmbclientsink);
  udpsmbclientSourceThread.join();
  cout << "Done Join udpsmbclient source" <<endl;
  udpsmbclientSinkThread.join();
  cout << "Done Join udpsmbclientsink" <<endl;

//  clientThread.join();
  return 0;
#endif
}

extern "C" void CommandProcessorPuts(char *buffer)
{
  cout << buffer;
//   UDPCommandSink->send_cstring(buffer);

}

void terminal_send(char *response)
{
  CommandProcessorPuts(response);
//  UDPCommandSink->send_cstring(response);
}
void log_send(char *message)
{

  CommandProcessorPuts(message);
//  UDPCommandSink->send_cstring(message);
}

extern "C" char *CommandProcessorGets(char *to, int max_count)
{
 cin.getline (to,max_count);
 return to;
// char *p = UDPCommandProcessor->PullNextCommandLine(to,max_count);
}


