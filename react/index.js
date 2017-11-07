import React from 'react';
import ReactDOM from 'react-dom';
const fs = window.require('fs');
const electron = window.require('electron');
const path = window.require('path');
const { execFile } = window.require('child_process');

require('typeface-alegreya-sans')
import './styles/main.css';
import './styles/modal.css';
import './styles/crashes.css';

import addButton from'./assets/plus.png';
import settingsButton from'./assets/settings.png';
import closeButton from'./assets/close.png';
import detailsButon from'./assets/details.png';

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
        let lib = process.platform === 'win32' ? 'taint.dll' : 'taint.so';
        let padding = Array(lib.length - 'pin.exe'.length).fill(<span>&nbsp;</span>);
        let data = Settings.get();
        return (
            <div className='modal'>
                <div className="heading_div">
                    <h1 className='heading red left'>Settings</h1>
                    <button onClick={this.saveSettings} className="img_btn right top_right_btn">
                        <img src={closeButton} className='img32'/>
                    </button>
                </div>
                <div className="modal_content">
                    <span className='red bold'>Pin path:</span><br />
                    {data['pin_path']}<br />

                    <span className='red bold'>Tool path:</span><br />
                    {data['triage_path']}<br />
                    <br />
                    <span className='red bold'>pin.exe:</span> {padding}<input type="file" ref="pin_path" /><br />
                    <span className='red bold'>{lib}:</span> <input type="file" ref="triage_path" /><br />
                </div>
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
            <div className="right">
                <button onClick={this.onClick} className='img_btn' alt="Settings">
                    <img src={settingsButton} className='img32 top_right_btn'/>
                </button>
                { this.state.showSettings ? <Settings close={this.childClose} save={this.childSave} /> : null }
            </div>
        );
    }
}

///////////////

class Crashes extends React.Component {
    constructor(props, context) {
        super(props, context);
        
        this.add = this.add.bind(this);
        this.run = this.run.bind(this);
        this.write = this.write.bind(this);
        this.refresh = this.refresh.bind(this);
        this.getSorted = this.getSorted.bind(this);

        this.state = {'updated': 0}

        this.queue = [];
        this.triaged = this.read();
        this.running = false;
    }

    add(cmd, filename) {
        console.log(cmd, filename);
        this.queue.push({'cmd': cmd, 'filename': filename});
        if(!this.running) { 
            this.run();
        }
    }

    write() {
        const userDataPath = (electron.app || electron.remote.app).getPath('userData');
        let filePath = path.join(userDataPath, 'crashes.json');

        fs.writeFileSync(filePath, JSON.stringify(this.triaged));
    }

    read() {
      const userDataPath = (electron.app || electron.remote.app).getPath('userData');
      let filePath = path.join(userDataPath, 'crashes.json');
      
      let data = [];
      try {
          data = JSON.parse(fs.readFileSync(filePath));
      } catch(error) {
          console.log("ERROR: no file");
      }

      return data;
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
                    this.write();
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

                this.refresh();
            });
    }

    getSorted() {
        return this.triaged.concat().sort(
            function(a, b) {
                if(!("crash_data" in a)) { 
                    return -1;
                }

                if(!("crash_data" in b)) { 
                    return 1;
                }

                let cda = a.crash_data;
                let cdb = b.crash_data;
                if(cda.score !== cdb.score) {
                    return cdb.score - cda.score;
                } else if(cda.signal !== cdb.signal) {
                    return cda.signal - cdb.signal;
                } else if(cda.reason !== cdb.reason) {
                    return cda.reason - cdb.reason;
                } else if(cda.location !== cdb.location) {
                    let loca_masked = cda.location & 0xFFF;
                    let locb_masked = cdb.location & 0xFFF;
                    return loca_masked - locb_masked;
                } 
            }
        );
    }

    refresh() {
        let upcount = this.state.updated;
        this.setState({'updated': upcount+1});
    }

    render() {
        return (
            <div>
                <CrashList getSorted={this.getSorted} key='crash_list' />
                <AddCrashButton add={this.add} key='add_crash_button' />
            </div>
        );
    }
}

class AddCrashModal extends React.Component {
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
        let padding = Array('Run command:'.length - 'File name:'.length).fill(<span>&nbsp;</span>);
        return (
            <div className='modal'>
                <div className="heading_div">
                    <h1 className='heading red left'>Add Crash</h1>
                    <button onClick={this.props.close} className='img_btn right top_right_btn'>
                        <img src={closeButton} className='img32'/>
                    </button>
                </div>
                <div className="modal_content">
                    <span className='red bold'>Run command: </span>
                    <input type="text" ref="cmd" defaultValue={test_cmd} className="add_cmd_input"/>
                    <br />

                    <span className='red bold'>File name: </span>{padding}
                    <input type="text" ref="filename" defaultValue={test_file} className="add_cmd_input"/>
                    <br />

                    <button onClick={this.saveCrash} className="add_cmd_save">Save</button>
                </div>
            </div>
        );
    }
};

class AddCrashButton extends React.Component {
    constructor(props, context) {
        super(props, context);

        this.state = {
          showModal: false
        }
        
        this.onClick = this.onClick.bind(this);
        this.childClose = this.childClose.bind(this);
        this.childSave = this.childSave.bind(this);
    }

    onClick() {
        this.setState({showModal: true });
    }

    childClose() {
        this.setState({showModal: false});
    }

    childSave(cmd, filename) {
        this.setState({showModal: false});
        this.props.add(cmd, filename);
    }

    render() {
        return (
            <div id="add_btn_div">
                <button onClick={this.onClick} className='img_btn' alt="Add Crash">
                    <img src={addButton} className='img48'/>
                </button>
                { this.state.showModal ? <AddCrashModal close={this.childClose} save={this.childSave} /> : null }
            </div>
        );
    }
}

class CrashDetailsModal extends React.Component {
    constructor(props, context) {
        super(props, context);
    }

    render() {
        console.log('render group', this.props.group);
        let crashes = [];
        for(var idx in this.props.group) {
            let crash = this.props.group[idx];
            crashes.push(
                <div key={idx}>
                    <div className='red bold'>{crash.crash_data.location.toString(16)}</div>
                    <div>{crash.cmd}</div>
                    <div>{crash.filename}</div>
                    <br/>
                </div>
            );
        }

        return (
            <div className='modal'>
                <div className="heading_div">
                    <h1 className='heading red left'>Crash Details</h1>
                    <button onClick={this.props.close} className='img_btn right top_right_btn'>
                        <img src={closeButton} className='img32'/>
                    </button>
                </div>
                <div className="modal_content">
                    <h2 className='bold red details_heading'>
                        {this.props.group[0].crash_data.score}
                        <span className='vr'></span>
                        {this.props.group[0].crash_data.reason}
                        <span className='vr'></span>
                        {this.props.group[0].crash_data.signal}
                    </h2>
                    <br />
                    {crashes}
                </div>
            </div>
        );
    }
};

class CrashList extends React.Component {
    constructor(props, context) {
        super(props, context);
        this.grouped = [];
        this.state = {
          showModal: false
        }
        this.childClose = this.childClose.bind(this);
        this.selected = [];
    }

    showCrash(idx) {
        this.selected = this.grouped[idx];
        this.setState({showModal: true});
    }

    childClose() {
        this.setState({showModal: false});
    }

    render() {
        let sorted = this.props.getSorted();

        let compare = {};
        if(sorted.length > 0) {
            compare = sorted[0];
        }

        let grouped = [];
        let group = [];
        for(var idx in sorted) {
            let crash = sorted[idx];
            let cd = crash.crash_data;
            let comp_cd = compare.crash_data;

            if(cd.score === comp_cd.score 
                && cd.signal === comp_cd.signal 
                && cd.reason === comp_cd.reason 
                && (cd.location & 0xFFF) === (comp_cd.location & 0xFFF)) 
            {
                group.push(crash);
            } else {
                compare = crash;
                grouped.push(group);
                group = [crash];
            }
        }

        grouped.push(group);
        this.grouped = grouped;

        let crash_list = [];
        for(var idx in grouped) {
            let group = grouped[idx];
            let crash = group[0];

            if(!('signal' in crash.crash_data)) {
                continue;
            }

            let cd = crash.crash_data;
            crash_list.push(
                <tr key={idx} className='crash_row'>
                    <td className='crash_column'>{cd.score}</td>
                    <td className='crash_column'>{cd.signal}</td>
                    <td className='crash_column'>{cd.reason}</td>
                    <td className='crash_column'>{cd.location.toString(16)}</td>
                    <td className='crash_column'>
                        <button className='img_btn'>
                            <img 
                                src={detailsButon} 
                                onClick={this.showCrash.bind(this, idx)} 
                                className='img16' />
                        </button>
                    </td>
                </tr>);
        }

        return (
            <div>
                <table className='crash_table'>
                    <tbody>
                        <tr>
                            <th>Score</th>
                            <th>Signal</th>
                            <th>Reason</th>
                            <th>Location</th>
                        </tr>
                        {crash_list}
                    </tbody>
                </table>
                { this.state.showModal ? <CrashDetailsModal close={this.childClose} group={this.selected}/> : null }
            </div>
        );
    }
}



///////////////

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

function Heading() {
    let text = 
        <h1 key="title" className="heading red left">
            Sienna Locomotive <span className="vr"></span> Triage
        </h1>;
    
    let hello = 
        <div className="heading_div">
            {text}
            <SettingsButton key="settings_button"/>
        </div>;
    return hello;

    // componentDidMount() {
    //     ready();
    // }
}

class Page extends React.Component {
  render() {
    return [
        <Heading key="heading" />, 
        // <Dropper key="dropper" />, 
        <Crashes key="crashes" />];
  }
}

ReactDOM.render(
    <Page />,
    root
);