//
//  OptionViewController.swift
//  RedOctober
//
//  Created by Longfei Li on 15/12/5.
//  Copyright © 2015年 Cody. All rights reserved.
//

import UIKit

class OptionViewController: UIViewController {

    @IBOutlet weak var addrText: UITextField!
    @IBOutlet weak var enterButton: UIButton!
    @IBOutlet weak var portText: UITextField!
    @IBOutlet weak var serverAddr: UILabel!
    override func viewDidLoad() {
        super.viewDidLoad()
        self.serverAddr.text! = Server.endpoint
        self.enterButton.layer.cornerRadius = 5
        self.enterButton.layer.borderWidth = 1
        self.enterButton.layer.borderColor = UIColor.whiteColor().CGColor
        self.portText.placeholder = "ex.8080"
        // Do any additional setup after loading the view.
    }
    

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    @IBAction func entered(sender: UIButton) {
        if(self.portText.text! != ""){
            Server.endpoint = self.addrText.text!+":"+self.portText.text!
        }else{
            Server.endpoint = self.addrText.text!
        }
        self.addrText.text! = "https://"
        self.portText.text!.removeAll()
        self.serverAddr.text! = Server.endpoint
    }

    /*
    // MARK: - Navigation

    // In a storyboard-based application, you will often want to do a little preparation before navigation
    override func prepareForSegue(segue: UIStoryboardSegue, sender: AnyObject?) {
        // Get the new view controller using segue.destinationViewController.
        // Pass the selected object to the new view controller.
    }
    */

}
