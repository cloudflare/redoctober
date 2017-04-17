//
//  WebViewController.swift
//  RedOctober
//
//  Created by Longfei Li on 15/12/4.
//  Copyright © 2015年 Cody. All rights reserved.
//

import UIKit
import WebKit

class WebViewController: UIViewController {

    
    @IBOutlet weak var containerView: UIWebView! = nil
    var webView: WKWebView?
    
    override func loadView() {
        super.loadView()
        self.webView = WKWebView()
        self.view = self.webView
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        print(Server.endpoint)
        if(Server.endpoint == "" || Server.endpoint == "https://"){
            let alertController = UIAlertController(title: "Server Unspecified", message:
                "Please go to Configuration and enter a server endpoint", preferredStyle: UIAlertControllerStyle.Alert)
            alertController.addAction(UIAlertAction(title: "Dismiss", style: UIAlertActionStyle.Default,handler: nil))
            
            self.presentViewController(alertController, animated: true, completion: nil)
        }
        // Do any additional setup after loading the view, typically from a nib.
        let url = NSURL (string: Server.endpoint);
        let requestObj = NSURLRequest(URL: url!);
        self.webView!.loadRequest(requestObj);
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
   // var endpoint = ""
    /*
    // MARK: - Navigation

    // In a storyboard-based application, you will often want to do a little preparation before navigation
    override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
        // Get the new view controller using segue.destinationViewController.
        // Pass the selected object to the new view controller.
    }
    */

}
