#include "Server.h"
#include <iostream>

#include "Logger.h"


int main()
{

    Logger::instance().init("server.log");
    LOG_INFO("Server starting...");
  
    Router router;
   
    ThreadPool pool(4);

    try
    {
        boost::asio::io_context io;

        Server server(io, 8080, pool, router);

        std::cout << "Server started on port 8080\n";

        io.run();
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
    }
}