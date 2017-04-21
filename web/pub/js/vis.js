vis = {};

function visReady() {
    vis.svg = d3.select('svg'),
    vis.margin = {top: 20, right: 20, bottom: 30, left: 50},
    vis.width = parseInt(vis.svg.style("width")) - vis.margin.left - vis.margin.right,
    vis.height = parseInt(vis.svg.style("height")) - vis.margin.top - vis.margin.bottom,
    vis.g = vis.svg.append("g")
        .attr("transform", "translate(" + vis.margin.left + "," + vis.margin.top + ")")
        .attr('id', 'vis_g');

    vis.x = d3.scaleTime()
        .rangeRound([0, vis.width]);

    vis.y = d3.scaleLinear()
        .rangeRound([vis.height, 0]);

    vis.line = d3.line()
        .x(function(d) { return vis.x(d.date); })
        .y(function(d) { return vis.y(d.execRate); });

    activeRuns();
    completeRuns();
    setInterval(function() {
        activeRuns();
        completeRuns();
    }, 3000);
}

function visualizeStats() {
    // unix_time
    // execs_per_sec
    // paths_total
    // unique_crashes
    vis.x.domain(d3.extent(vis.data, function(d) { return d.date; }));
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execRate; }));

    vis.axisBottom = vis.g.append("g");
    vis.axisBottom
      .attr("transform", "translate(0," + vis.height + ")")
      .call(d3.axisBottom(vis.x));

    vis.axisLeft = vis.g.append("g");
    vis.axisLeft
      .call(d3.axisLeft(vis.y))
    .append("text")
      .attr("fill", "#000")
      .attr("transform", "rotate(-90)")
      .attr("y", 6)
      .attr("dy", "0.71em")
      .attr("text-anchor", "end")
      .text("execs / second");

    vis.path = vis.g.append("path");
    vis.path
      .attr("fill", "none")
      .attr("stroke", "steelblue")
      .attr("stroke-linejoin", "round")
      .attr("stroke-linecap", "round")
      .attr("stroke-width", 1.5)
      .attr("d", vis.line(vis.data));

}

function updateVisualize() {
    vis.x.domain(d3.extent(vis.data, function(d) { return d.date; }));
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execRate; }));

    vis.axisLeft
        .transition()
        .duration(750)
        .call(d3.axisLeft(vis.y));

    vis.axisBottom
        .transition()
        .duration(750)
        .call(d3.axisBottom(vis.x));

    vis.path
        .transition()
        .duration(750)
        .attr('d', vis.line(vis.data));
}

function runStatsSuccess(data) {
    // check stats
    var empty = true;
    for(var idx in data) {
        if(data[idx].length > 0) {
            empty = false;
            break;
        }
    }

    if(empty)
        return;

    // extract data we want
    var stats = [];
    var recent = [];
    for(var widx in data) {
        var worker_stats = data[widx];
        for(sidx in worker_stats) {
            var unix = worker_stats[sidx]['stats'].last_update;
            var execRate = parseInt(worker_stats[sidx]['stats'].execs_per_sec);
            var paths = worker_stats[sidx]['stats'].paths_total;
            var crashes = parseInt(worker_stats[sidx]['stats'].unique_crashes);
            var execsTotal = parseInt(worker_stats[sidx]['stats'].execs_done);

            var stat = {}
            stat.execsTotal = execsTotal;
            stat.date = new Date(unix*1000);
            stat.execRate = execRate;
            stat.paths = paths;
            stat.crashes = crashes;
            stat.worker = widx;

            if(worker_stats[sidx]['fuzzers'] == 'winafl') {
                stat.hangs = parseInt(worker_stats[sidx]['stats'].unique_hangs);
            }

            stats.push(stat);
        }

        recent.push({
            'execRate': 0, 
            'paths': 0,
            'crashes':0,
            'date': undefined,
        });
    }

    // sort by date
    stats.sort(function(a, b) {
        var da = a.date;
        var db = b.date;

        if(da < db)
            return -1;
        if(da > db)
            return 1;
        return 0;
    });

    // array for tracking total execs
    var totals = [];
    for(var idx in stats) {
        var total = {};
        var stat = stats[idx];
        recent[stat.worker] = stat;
        total.date = stat.date;
        total.execRate = 0;
        for(var idx in recent) {
            total.execRate += recent[idx].execRate;
        }
        totals.push(total);
    }

    vis.data = totals;

    if($('svg').children().children().length == 0) {
        visualizeStats();
    } else {
        updateVisualize();
    }

    return recent;
}

function buildWorkerStats(status, stat) {
    // TODO: reuse existing rows
    var colWidth = '_25';

    if('hangs' in stat) {
        colWidth = '_20';
    }

    var workerDiv = $('<div></div>');
    workerDiv.addClass('worker_div');
    workerDiv.addClass('row');

    var statusSpan = $('<span></span>');
    statusSpan.addClass('column ' + colWidth);
    statusSpan.text(status);

    var execsSpan = $('<span></span>');
    execsSpan.addClass('column ' + colWidth);
    execsSpan.text(stat.execRate + ' execs/s');

    var pathsSpan = $('<span></span>');
    pathsSpan.addClass('column ' + colWidth);
    pathsSpan.text(stat.paths + ' paths');

    var crashesSpan = $('<span></span>');
    crashesSpan.addClass('column ' + colWidth);
    crashesSpan.text(stat.crashes + ' crashes');

    workerDiv.append(statusSpan);
    workerDiv.append(execsSpan);
    workerDiv.append(pathsSpan);
    workerDiv.append(crashesSpan);

    if('hangs' in stat) {
        var hangsSpan = $('<span></span>');
        hangsSpan.addClass('column ' + colWidth);
        hangsSpan.text(stat.hangs + ' hangs');
        workerDiv.append(hangsSpan);
    }

    $('#worker_stats_div').append(workerDiv);
}

function buildRunStats(stats) {
    // status
    // total execs
    // average exec speed
    var execs = 0;
    var crashes = 0;
    var totalRate = 0;

    for(var idx in stats) {
        var stat = stats[idx];
        totalRate += stat.execRate;
        execs += stat.execsTotal;
        crashes += stat.crashes;
        if('hangs' in stat)
            crashes += stat.hangs;
    }

    $('#run_rate_span').text(totalRate + ' execs/s');
    $('#run_execs_span').text(execs.toLocaleString() + ' execs');
    $('#run_crashes_span').text(crashes + ' potential crashes');
}

function runStatusSuccess(statuses, stats) {
    // TODO: hide stats until we have something
    $('#worker_stats_div').empty();
    for(var idx in statuses) {
        var status = statuses[idx];
        if(stats === undefined) {
            var stat = {
                'execs': 0,
                'execRate': 0,
                'crashes': 0,
                'paths': 0
            };
        } else {
            var stat = stats[idx];
        }

        buildWorkerStats(status, stat);
    }
    buildRunStats(stats);
}

function initShowLink(sysId, progId, runId, info) {
    return function() {
        $('#system_select').val(sysId);
        systemSelect(false);

        programList(true, sysId, progId);

        runList(true, progId, runId);

        $('#run_status_span').text(info['status']);
        // $('#run_runtime_span').text(info['run_time']);
    }
}

function displayRuns(type, data) {
    var runs = data['runs'];
    $('#'+type+'_runs_div').empty();

    for(var idx in runs) {
        var run = runs[idx];
        var name = run['name'];
        var start = new Date(parseInt(run['start_time']) * 1000);
        var end = new Date(parseInt(run['end_time']) * 1000);
        var status = run['status'];

        var runDiv = $('<div></div>');
        runDiv.addClass('run_'+type+'_div');
        runDiv.addClass('row');

        var nameSpan = $('<span></span>');
        nameSpan.addClass('column _25');
        nameSpan.text(name);

        var startSpan = $('<span></span>');
        startSpan.addClass('column _25');
        startSpan.text(start.toString().split(' ').splice(1, 4).join(' '));


        var now = new Date();
        var diff = now - start;
        var hours = parseInt((diff / 1000) / 3600)
        var minutes = parseInt((diff / 1000) / 60) - 60 * hours;
        var runTime = hours+'h:'+minutes+'m';

        var endSpan = $('<span></span>');
        endSpan.addClass('column _25');

        if(type != 'active') {
            endSpan.text(end.toString().split(' ').splice(1, 4).join(' '));
        } else {
            endSpan.text(runTime);
        }

        var showSpan = $('<span></span>');
        showSpan.addClass('column _25');
        var showLink = $('<a></a>');
        showLink.attr('href', '#');

        var sysId = run['system'];
        var progId = run['program'];
        var runId = run['_id'];
        var info = { 'status': status, 'run_time': runTime };
        showLink.on('click', initShowLink(sysId, progId, runId, info));
        
        showLink.text('Show');
        showSpan.append(showLink);

        runDiv.append(nameSpan);
        runDiv.append(startSpan);
        runDiv.append(endSpan);
        runDiv.append(showSpan);

        $('#'+type+'_runs_div').append(runDiv);
    }
}

function activeRuns() {
    $.ajax({
        type: 'GET',
        url: '/run_active_list', 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            displayRuns('active', data);
        }
    });    
}

function completeRuns() {
    $.ajax({
        type: 'GET',
        url: '/run_complete_list', 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            displayRuns('finished', data);
        }
    });    
}

function runStats(runId) {
    var checkId = $('#run_select').val();
    
    if(runId == undefined) {
        $('svg').children().empty();
        runId = checkId;
    }

    if(runId != checkId)
        return;

    if(runId == '--')
        return;

    $.ajax({
        type: 'GET',
        url: '/run_stats_all/' + runId, 
        success: function(data) {
            data = JSON.parse(data);
            if('error' in data) {
                handleError(data);
                return;
            } 

            var recentStats = runStatsSuccess(data['stats']);
            runStatusSuccess(data['status'], recentStats);
            
            var statsDiv = $('#run_stats');
            if(statsDiv.is(':hidden')) {
                statsDiv.show();
            }

        }
    });

    setTimeout(function() {
        runStats(runId);
    }, 3000);
}
