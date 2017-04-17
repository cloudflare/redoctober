//
//  ViewController.swift
//  RedOctober
//
//  Created by Longfei Li on 15/12/4.
//  Copyright © 2015年 Cody. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func helpButtonPressed(sender: UIButton) {
        let email = "codyli520@gmail.com"
        let url = NSURL(string: "mailto:\(email)")
        UIApplication.sharedApplication().openURL(url!)
    }
    

}

