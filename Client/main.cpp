#include "Client.h"


int main(int argc, char* argv[])
{
    try
    {
        boost::asio::io_context io_context;
        Client c(io_context);

        std::thread t([&io_context]() { io_context.run(); });

        c.run();

        c.close();
        t.join();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}