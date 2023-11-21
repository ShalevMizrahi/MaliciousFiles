import os
import requests

def upload (path, url, headers):
    upload_url = url + "files"
    files = {"file" :(
            os.path.basename(path),
            open(os.path.abspath(path), "rb"))}
    res = requests.post(upload_url, headers = headers, files = files)
    if res.status_code == 200:
        file_id = res.json().get("data").get("id")
        print("successfully upload PE file: OK")
    else:
        print(":(")

    return file_id

def analyse(url, headers, fileID):
    analysis_url = url + "analyses/" + fileID
    res = requests.get(analysis_url, headers = headers)
    if res.status_code == 200:
        result = res.json()
        status = result.get("data").get("attributes").get("status")
        if status == "completed":
            stats = result.get("data").get("attributes").get("stats")
            results = result.get("data").get("attributes").get("results")
            print ("malicious: " + str(stats.get("malicious")))
            print ("undetected : " + str(stats.get("undetected")))
            print ()
            for k in results:
                if results[k].get("category") == "malicious":
                    print ("==================================================")
                    print (results[k].get("engine_name"))
                    print ("version : " + results[k].get("engine_version"))
                    print ("category : " + results[k].get("category"))
                    print ("result : " + results[k].get("result"))
                    print ("method : " + results[k].get("method"))
                    print ("update : " + results[k].get("engine_update"))
                    print ("==================================================")
                    print ()
            print ("successfully analyse: OK")
    else:
        print ("failed to get results of analysis :(")
        print ("status code: " + str(res.status_code))            




def main():

    VT_API_KEY = "765b9f300141f8d3f1351ff309da65fb08dd45577abac0e0739fd5ff1137d993"    
    VT_API_URL = "https://www.virustotal.com/api/v3/"
    headers = {
            "x-apikey" : VT_API_KEY,
            "User-Agent" : "vtscan v.1.0",
            "Accept-Encoding" : "gzip, deflate",
        }
    fileID = upload("C:\Homework\Python\youngfortech.py", VT_API_URL, headers)
    analyse(VT_API_URL, headers, fileID)




if __name__ == "__main__":
    main()