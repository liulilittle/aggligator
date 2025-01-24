#include "aggligator.h"
#include "DateTime.h"

static std::shared_ptr<boost::asio::io_context> context_;
static std::shared_ptr<aggligator::aggligator> app_;

static void aggligator_exit(boost::asio::io_context& context, bool shutdown = true)
{
    context.dispatch(
        [&context, shutdown]() noexcept
        {
            static bool exited = false;

            if (!exited)
            {
                exited = true;
                aggligator::HideConsoleCursor(false);

                if (shutdown)
                {
                    printf("%s\r\n", "Application is shutting down...");
                }

                std::shared_ptr<aggligator::aggligator> aggligator = std::move(app_);
                app_.reset();

                if (aggligator)
                {
                    aggligator->close();
                }
            }

            std::shared_ptr<boost::asio::deadline_timer> t = aggligator::make_shared_object<boost::asio::deadline_timer>(context);
            if (!t)
            {
                context.stop();
            }
            else
            {
                t->expires_from_now(boost::posix_time::milliseconds(1000));
                t->async_wait(
                    [&context, t](boost::system::error_code ec) noexcept
                    {
                        context.stop();
                    });
            }
        });
}

static void aggligator_help() noexcept
{
    aggligator::string execution_file_name = aggligator::GetExecutionFileName();
    aggligator::string messages = "Copyright (C) 2017 ~ 2055 SupersocksR ORG. All rights reserved.\r\n";
    messages += "Aggligator(X) 1.0.0.25053 Version\r\n";
    messages += "Cwd:\r\n    " + aggligator::GetCurrentDirectoryPath() + "\r\n";
    messages += "Usage:\r\n";
    messages += "        ./%s --mode=server --flash=yes --congestions=1024 --bind=10000,10001 --host=192.168.0.24:7000 \r\n";
    messages += "        ./%s --mode=client --flash=yes --congestions=1024 --connections=1 --bind=9999 --host=127.0.0.1:10000,127.0.0.1:10001 \r\n";
    messages += "Contact us:\r\n";
    messages += "    https://t.me/supersocksr_group \r\n";
    printf(messages.data(), execution_file_name.data(), execution_file_name.data()), aggligator::HideConsoleCursor(false);
}

static bool aggligator_is_mode_client_or_server(int argc, const char* argv[]) noexcept
{
    static constexpr const char* keys[] = { "--mode", "--m", "-mode", "-m" };

    aggligator::string mode_string;
    for (const char* key : keys)
    {
        mode_string = aggligator::GetCommandArgument(key, argc, argv);
        if (mode_string.size() > 0)
        {
            break;
        }
    }

    if (mode_string.empty())
    {
        mode_string = "server";
    }

    mode_string = aggligator::ToLower<aggligator::string>(mode_string);
    mode_string = aggligator::LTrim<aggligator::string>(mode_string);
    mode_string = aggligator::RTrim<aggligator::string>(mode_string);
    return mode_string.empty() ? false : mode_string[0] == 'c';
}

static bool aggligator_run(boost::asio::io_context& context, bool client_or_server, int connections, int congestions, aggligator::unordered_set<int>& bind, aggligator::unordered_set<boost::asio::ip::tcp::endpoint>& host) noexcept
{
    auto buffer = aggligator::make_shared_alloc<aggligator::Byte>(UINT16_MAX);
    if (!buffer)
    {
        return false;
    }

    auto app = aggligator::make_shared_object<aggligator::aggligator>(context, buffer, UINT16_MAX, congestions);
    if (!app)
    {
        return false;
    }

    class network_statistics
    {
    public:
        uint64_t pps;
        uint64_t rx_pps;
        uint64_t tx_pps;
        uint64_t rx;
        uint64_t tx;
        int      cx;
        int      cy;
        aggligator::DateTime start;
    };

    std::shared_ptr<network_statistics> statistics = aggligator::make_shared_object<network_statistics>();
    if (!statistics)
    {
        return false;
    }

    statistics->rx_pps = 0;
    statistics->tx_pps = 0;
    statistics->pps = 0;
    statistics->rx = 0;
    statistics->tx = 0;
    statistics->cx = 0;
    statistics->cy = 0;
    statistics->start = aggligator::DateTime::Now();

    aggligator::aggligator* my = app.get();
    app->Tick =
        [my, statistics](uint64_t now) noexcept
        {
            aggligator::aggligator::information info;
            if (!my->info(info))
            {
                return false;
            }

            if (!aggligator::SetConsoleCursorPosition(0, 0))
            {
                return false;
            }

            int x, y;
            if (!aggligator::GetConsoleWindowSize(x, y))
            {
                return false;
            }

            if (x != statistics->cx || y != statistics->cy)
            {
                statistics->cx = x;
                statistics->cy = y;
                aggligator::ClearConsoleOutputCharacter();
            }

            aggligator::string content;
            int content_line_count = 0;
            auto println =
                [&content, x, y, &content_line_count](const aggligator::string& in) noexcept
                {
                    if (content_line_count < y)
                    {
                        content_line_count++;
                        content += aggligator::PaddingRight<aggligator::string>(in, x, ' ');
                    }
                };

            println("Application started. Press Ctrl+C to shut down.");
            println("Process               : " + std::to_string(aggligator::GetCurrentProcessId()));
            println("Cwd                   : " + aggligator::GetCurrentDirectoryPath());

            if (!my->server_mode())
            {
                aggligator::string link_state = "established";
                if (info.bind_ports.empty())
                {
                    link_state = info.client_count > 0 ? "connecting" : "reconnecting";
                }

                println("State                 : " + link_state);
            }

            int i = 0;
            println("Duration              : " + (aggligator::DateTime::Now() - statistics->start).ToString("TT:mm:ss", false));
            for (int bind_port : info.bind_ports)
            {
                println(aggligator::PaddingRight<aggligator::string>("Listen Port " + std::to_string(++i), 22, ' ') + ": " + std::to_string(bind_port));
            }
            
            i = 0;
            for (auto&& ep : info.server_endpoints)
            {
                println(aggligator::PaddingRight<aggligator::string>("Server Addresss " + std::to_string(++i), 22, ' ') + ": " + ep.address().to_string() + ":" + std::to_string(ep.port()));
            }

            println("Number of connections : " + std::to_string(info.connection_count));
            println("Number of links       : " + std::to_string(info.establish_count) + " [ready]");
            println("Number of sessions    : " + std::to_string(info.client_count));

            uint64_t pps = info.rx_pps + info.tx_pps;
            println("Packets per second    : " + std::to_string(pps - statistics->pps));
            println("RX                    : " + aggligator::StrFormatByteSize(info.rx - statistics->rx));
            println("TX                    : " + aggligator::StrFormatByteSize(info.tx - statistics->tx));

            println("Incoming Unicast      : " + std::to_string(info.rx_pps));
            println("Outgoing Unicast      : " + std::to_string(info.tx_pps));
            println("Incoming Traffic      : " + aggligator::StrFormatByteSize(info.rx));
            println("Outgoing Traffic      : " + aggligator::StrFormatByteSize(info.tx));

#if defined(_DEBUG)
            println("Hosting Environment   : " + aggligator::string(my->server_mode() ? "server:development" : "client:development"));
#else
            println("Hosting Environment   : " + aggligator::string(my->server_mode() ? "server:production" : "client:production"));
#endif

            statistics->rx_pps = info.rx_pps;
            statistics->tx_pps = info.tx_pps;
            statistics->pps = pps;
            statistics->rx = info.rx;
            statistics->tx = info.tx;

            fprintf(stdout, "%s", content.data());
            return true;
        };

    std::shared_ptr<bool> opened = aggligator::make_shared_object<bool>(false);
    if (!opened)
    {
        return false;
    }

    if (client_or_server)
    {
        auto tail = bind.begin();
        *opened = app->client_open(connections, *tail, host);
    }
    else
    {
        auto tail = host.begin();
        *opened = app->server_open(bind, tail->address(), tail->port());
    }

    if (*opened)
    {
        std::weak_ptr<bool> opened_weak = opened;
        app_ = app;
        app->Exit =
            [&context, opened_weak]() noexcept
            {
                std::shared_ptr<bool> opened = opened_weak.lock();
                if (opened)
                {
                    *opened = false;
                }

                aggligator_exit(context);
            };
        return *opened;
    }

    app->close();
    return false;
}

static aggligator::string aggligator_format_list_string(const aggligator::string& in) noexcept
{
    if (in.empty())
    {
        return aggligator::string();
    }

    aggligator::string result = in;
    result = aggligator::Replace<aggligator::string>(result, ";", ",");
    result = aggligator::Replace<aggligator::string>(result, " ", ",");
    result = aggligator::Replace<aggligator::string>(result, "|", ",");
    result = aggligator::Replace<aggligator::string>(result, "+", ",");
    result = aggligator::Replace<aggligator::string>(result, "*", ",");
    result = aggligator::Replace<aggligator::string>(result, "^", ",");
    result = aggligator::Replace<aggligator::string>(result, "&", ",");
    result = aggligator::Replace<aggligator::string>(result, "#", ",");
    result = aggligator::Replace<aggligator::string>(result, "@", ",");
    result = aggligator::Replace<aggligator::string>(result, "!", ",");
    result = aggligator::Replace<aggligator::string>(result, "'", ",");
    result = aggligator::Replace<aggligator::string>(result, "\"", ",");
    result = aggligator::Replace<aggligator::string>(result, "?", ",");
    result = aggligator::Replace<aggligator::string>(result, "%", ",");
    result = aggligator::Replace<aggligator::string>(result, "[", ",");
    result = aggligator::Replace<aggligator::string>(result, "]", ",");
    result = aggligator::Replace<aggligator::string>(result, "{", ",");
    result = aggligator::Replace<aggligator::string>(result, "}", ",");
    result = aggligator::Replace<aggligator::string>(result, "\\", ",");
    result = aggligator::Replace<aggligator::string>(result, "/", ",");
    result = aggligator::Replace<aggligator::string>(result, "-", ",");
    result = aggligator::Replace<aggligator::string>(result, "_", ",");
    result = aggligator::Replace<aggligator::string>(result, "=", ",");
    result = aggligator::Replace<aggligator::string>(result, "`", ",");
    result = aggligator::Replace<aggligator::string>(result, "~", ",");
    result = aggligator::Replace<aggligator::string>(result, "\r", ",");
    result = aggligator::Replace<aggligator::string>(result, "\n", ",");
    result = aggligator::Replace<aggligator::string>(result, "\t", ",");
    result = aggligator::Replace<aggligator::string>(result, "\a", ",");
    result = aggligator::Replace<aggligator::string>(result, "\b", ",");
    result = aggligator::Replace<aggligator::string>(result, "\v", ",");
    result = aggligator::Replace<aggligator::string>(result, "\f", ",");
    return result;
}

static bool aggligator_string_many_argument(const char* name, int argc, const char* argv[], std::function<void(aggligator::string&)> predicate) noexcept
{
    aggligator::string strings = aggligator_format_list_string(aggligator::GetCommandArgument(name, argc, argv));
    if (strings.empty())
    {
        return false;
    }

    aggligator::vector<aggligator::string> lines;
    aggligator::Tokenize<aggligator::string>(strings, lines, ",");
    if (lines.empty()) 
    {
        return false;
    }

    
    bool success = false;
    for (size_t i = 0, l = lines.size(); i < l; i++)
    {
        aggligator::string line = aggligator::ATrim(lines[i]);
        if (line.empty())
        {
            continue;
        }

        predicate(line);
    }
    return success;
}

static bool aggligator_port_many_argument(const char* name, int argc, const char* argv[], aggligator::unordered_set<int>& out) noexcept
{
    return aggligator_string_many_argument(name, argc, argv,
        [&out](aggligator::string& line) noexcept
        {
            int port = atoi(line.data());
            if (port > 0 && port <= UINT16_MAX)
            {
                out.emplace(port);
            }
        });
}

static bool aggligator_ip_endpoint_many_argument(const char* name, int argc, const char* argv[], aggligator::unordered_set<boost::asio::ip::tcp::endpoint>& out) noexcept
{
    return aggligator_string_many_argument(name, argc, argv,
        [&out](aggligator::string& line) noexcept
        {
            std::size_t index = line.find(":");
            if (index != aggligator::string::npos)
            {
                int port = atoi(line.substr(index + 1).data());
                if (port > 0 || port <= UINT16_MAX)
                {
                    boost::system::error_code ec;
                    std::string host = line.substr(0, index);
                    boost::asio::ip::address address = aggligator::StringToAddress(host.data(), ec);
                    if (ec == boost::system::errc::success && !aggligator::aggligator::ip_is_invalid(address))
                    {
                        out.emplace(boost::asio::ip::tcp::endpoint(address, port));
                    }
                }
            }
        });
}

int main(int argc, const char* argv[]) noexcept
{
    aggligator::SetThreadPriorityToMaxLevel();
    aggligator::SetProcessPriorityToMaxLevel();
    aggligator::HideConsoleCursor(true);
    aggligator::AddShutdownApplicationEventHandler(
        []() noexcept
        {
            std::shared_ptr<boost::asio::io_context> ctx = context_;
            if (ctx)
            {
                aggligator_exit(*ctx);
            }

            return true;
        });

#if defined(JEMALLOC)
    aggligator::aggligator::jemaillc_areans_set_default();
#endif

    if (aggligator::IsInputHelpCommand(argc, argv))
    {
        aggligator_help();
        return 0;
    }

    context_ = aggligator::make_shared_object<boost::asio::io_context>();
    if (!context_)
    {
        aggligator_help();
        return -1;
    }

    boost::asio::io_context::work work(*context_);
    context_->post(
        [argc, argv]() noexcept
        {
            bool client_or_server = aggligator_is_mode_client_or_server(argc, argv);
            int connections = atoi(aggligator::GetCommandArgument("--connections", argc, argv).data());
            if (connections < 1)
            {
                connections = 4;
            }

            int congestions = atoi(aggligator::GetCommandArgument("--congestions", argc, argv).data());
            if (congestions < 0)
            {
                congestions = 0;
            }

            aggligator::unordered_set<int> bind;
            aggligator_port_many_argument("--bind", argc, argv, bind);

            aggligator::unordered_set<boost::asio::ip::tcp::endpoint> host;
            aggligator_ip_endpoint_many_argument("--host", argc, argv, host);

            aggligator::aggligator::socket_flash_mode(aggligator::ToBoolean(aggligator::GetCommandArgument("--flash", argc, argv).data()));

            bool opened = false;
            if (!bind.empty() && !host.empty())
            {
                opened = aggligator_run(*context_, client_or_server, connections, congestions, bind, host);
            }

            if (!opened)
            {
                aggligator_help();
                aggligator_exit(*context_, false);
            }

            return opened;
        });

    boost::system::error_code ec;
    context_->run(ec);
    return 0;
}