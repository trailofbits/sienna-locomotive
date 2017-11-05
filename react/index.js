import React from 'react';
import ReactDOM from 'react-dom';
const fs = window.require('fs');
const electron = window.require('electron');
const path = window.require('path');
const { execFile } = window.require('child_process');

import './styles/modal.css';

let root = document.getElementById('root');

/*

SETTINGS
    Pin Path
    Pintool Path

TRIAGE CRASH(ES)?
    Program CMD line
    Target file
    Bulk Uploader
    Run + extract JSON
    Add jobs to queue, async execute and pop jobs

CRASH LISTING
    Crashing address
    Score
    Crashing reason

*/

class Settings extends React.Component {
    constructor(props, context) {
        super(props, context);
        this.saveSettings = this.saveSettings.bind(this);
    }

    saveSettings() {
        let pin_path = '';
        let triage_path = '';

        if(this.refs.pin_path.files.length > 0) {
            pin_path = this.refs.pin_path.files[0].path;
        }
        if(this.refs.triage_path.files.length > 0) {
            triage_path = this.refs.triage_path.files[0].path;
        }

        Settings.set(pin_path, triage_path);
        this.props.close();
    }

    static set(pin_path, triage_path) {
        const userDataPath = (electron.app || electron.remote.app).getPath('userData');
        let filePath = path.join(userDataPath, 'settings.json');

        let data = {'pin_path': '', 'triage_path': ''};
        try {
            data = JSON.parse(fs.readFileSync(filePath));
        } catch(error) {
            console.log("ERROR: no file");
        }

        if(pin_path !== '') {
            data['pin_path'] = pin_path;
        }
        
        if(triage_path !== '') {
            data['triage_path'] = triage_path;
        }

        fs.writeFileSync(filePath, JSON.stringify(data));
    }

    static get() {
      const userDataPath = (electron.app || electron.remote.app).getPath('userData');
      let filePath = path.join(userDataPath, 'settings.json');
      
      let data = {'pin_path': '', 'triage_path': ''};
      try {
          data = JSON.parse(fs.readFileSync(filePath));
      } catch(error) {
          console.log("ERROR: no file");
      }

      return data;
    }

    render() {
        let lib = process.platform === 'win32' ? 'triage.dll' : 'triage.so';
        let data = Settings.get();
        return (
            <div className='modal'>
                <h2>Settings</h2>
                pin_path: {data['pin_path']}<br />
                triage_path: {data['triage_path']}<br />
                <br />
                pin.exe: <input type="file" ref="pin_path" /><br />
                {lib}: <input type="file" ref="triage_path" /><br />
                <button onClick={this.saveSettings}>Close</button>
            </div>
        );
    }
};

class SettingsButton extends React.Component {
    constructor(props, context) {
        super(props, context);

        this.state = {
          showSettings: false
        }
        
        this.onClick = this.onClick.bind(this);
        this.childClose = this.childClose.bind(this);
        this.childSave = this.childSave.bind(this);
    }

    onClick() {
        this.setState({ showSettings: true });
    }

    childClose() {
        this.setState({showSettings: false});
        console.log(this.state);
    }

    childSave(pin_path, triage_path) {
        this.setState({'pin_path': pin_path, 'triage_path': triage_path});
    }

    render() {
        console.log("RENDER", this.state);
        return (
            <div>
                <button onClick={this.onClick}>Settings</button>
                { this.state.showSettings ? <Settings close={this.childClose} save={this.childSave} /> : null }
            </div>
        );
    }
}

///////////////

class Crashes {
    constructor() {
        this.add = this.add.bind(this);
        this.run = this.run.bind(this);

        this.queue = [];
        this.triaged = [];
        this.running = false;
    }

    add(cmd, filename) {
        console.log(cmd, filename);
        this.queue.push({'cmd': cmd, 'filename': filename});
        if(!this.running) { 
            this.run();
        }
    }

    run() {
        this.running = true;
        let settings = Settings.get();
        let job = this.queue.shift();
        this.triaged.push(job);

        let args = [
            '-t', settings['triage_path'], 
            '-f',  job['filename'], 
            '--'
        ];

        args = args.concat(job['cmd'].match(/[^" ]+|"[^"]+"/g));
        console.log('args', args);

        const child = execFile(settings['pin_path'], args,
            (error, stdout, stderr) => {
                let start = '#### BEGIN CRASH DATA JSON';
                let end = '#### END CRASH DATA JSON';
                if(stdout.includes(start) && stdout.includes(end)) {
                    let json_str = stdout.split(start)[1].split(end)[0];
                    let crash_data = JSON.parse(json_str);
                    console.log(crash_data);

                    let job = this.triaged.pop();
                    job['crash_data'] = crash_data;
                    this.triaged.push(job);
                } else if (error) {
                    this.running = false;
                    console.log(stdout);
                    console.log(stderr);
                    throw error;
                } else {
                    console.log('Unknown error!');
                }

                if(this.queue.length !== 0) {
                    console.log("Running next!");
                    this.run();
                } else {
                    console.log("Empty queue!");
                    this.running = false;
                }
            });
    }
}

let crashes = new Crashes;
global['crashes'] = crashes;

class AddCrash extends React.Component {
    constructor(props, context) {
        super(props, context);
        this.saveCrash = this.saveCrash.bind(this);
    }

    saveCrash() {
        let cmd = this.refs.cmd.value;
        let filename = this.refs.filename.value;
        this.props.save(cmd, filename);
    }

    render() {
        let test_file = 'crash_scratch';
        let test_cmd = '/home/taxicat/work/sienna-locomotive/triage/corpus/asm/crashy_mccrashface 3';
        return (
            <div className='modal'>
                <h2>Add Crash</h2>
                Run command: <input type="text" ref="cmd" defaultValue={test_cmd}/><br />
                File name: <input type="text" ref="filename" defaultValue={test_file}/><br />
                <button onClick={this.props.close}>Close</button>
                <button onClick={this.saveCrash}>Save</button>
            </div>
        );
    }
};

class AddCrashButton extends React.Component {
    constructor(props, context) {
        super(props, context);

        this.state = {
          showDialog: false
        }
        
        this.onClick = this.onClick.bind(this);
        this.childClose = this.childClose.bind(this);
        this.childSave = this.childSave.bind(this);
    }

    onClick() {
        this.setState({showDialog: true });
    }

    childClose() {
        this.setState({showDialog: false});
    }

    childSave(cmd, filename) {
        this.setState({showDialog: false});
        crashes.add(cmd, filename);
    }

    render() {
        return (
            <div>
                <button onClick={this.onClick}>Add Crash</button>
                { this.state.showDialog ? <AddCrash close={this.childClose} save={this.childSave} /> : null }
            </div>
        );
    }
}

function Dropper() {
    let text = "Drag files here!";
    
    let holder = 
        <div key="holder" id="holder">
            <p>{text}</p>
        </div>;
    return holder;
}

function ready() {
    document.getElementById("holder").addEventListener('drop', function (e) {
      e.preventDefault();
      e.stopPropagation();
      
      for (let f of e.dataTransfer.files) {
        console.log('File(s) you dragged here: ', f.path)
      }
    });

    document.addEventListener('dragover', function (e) {
      e.preventDefault();
      e.stopPropagation();
    });
}

///////////////

function Greeting() {
    let text = <h1 key="title">Hello world!</h1>;
    
    let hello = 
        <div key="hello" id="greeting">
            {text}
        </div>;
    return hello;
}

class Page extends React.Component {
  render() {
    return [<Greeting key="greeting" />, <Dropper key="dropper" />, <SettingsButton key="settings_button" />, <AddCrashButton key="add_crash_button" />];
  }

  componentDidMount() {
    ready();
  }
}

ReactDOM.render(
    <Page />,
    root
);