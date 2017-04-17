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
        .y(function(d) { return vis.y(d.execs); });

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
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execs; }));

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
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execs; }));

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
            var unix = worker_stats[sidx]['stats'].unix_time;
            var execs = parseInt(worker_stats[sidx]['stats'].execs_per_sec);
            var paths = worker_stats[sidx]['stats'].paths_total;
            var crashes = worker_stats[sidx]['stats'].unique_crashes;

            var stat = {}
            stat.date = new Date(unix*1000);
            stat.execs = execs;
            stat.paths = paths;
            stat.crashes = crashes;
            stat.worker = widx;
            stats.push(stat);
        }

        recent.push({
            'execs': 0, 
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
        total.execs = recent.reduce(function(a, b) { 
            return a.execs + b.execs; }, {'execs': 0});
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

function runStatusSuccess(statuses, stats) {
    for(var idx in statuses) {
        var status = statuses[idx];
        if(stats === undefined) {
            var stats = {
                'execs': 0,
                'crashes': 0,
                'paths': 0
            };
        } else {
            var stats = stats[idx];
        }

        var workerDiv = $('<div></div>');
        workerDiv.addClass('worker_div');
        workerDiv.addClass('row');

        var statusSpan = $('<span></span>');
        statusSpan.addClass('column');
        statusSpan.addClass('_25');
        statusSpan.text(status);

        var execsSpan = $('<span></span>');
        execsSpan.addClass('column');
        execsSpan.addClass('_25');
        execsSpan.text(stats.execs + ' execs/s');

        var pathsSpan = $('<span></span>');
        pathsSpan.addClass('column');
        pathsSpan.addClass('_25');
        pathsSpan.text(stats.paths + ' paths');

        var crashesSpan = $('<span></span>');
        crashesSpan.addClass('column');
        crashesSpan.addClass('_25');
        crashesSpan.text(stats.crashes + ' crashes');

        workerDiv.append(statusSpan);
        workerDiv.append(execsSpan);
        workerDiv.append(pathsSpan);
        workerDiv.append(crashesSpan);

        $('#worker_stats_div').empty();
        $('#worker_stats_div').append(workerDiv);
    }
}

function initShowLink(sysId, progId, runId) {
    return function() {
        $('#system_select').val(sysId);
        systemSelect(false);

        programList(true, sysId, progId);

        runList(true, progId, runId);
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

        var runDiv = $('<div></div>');
        runDiv.addClass('run_'+type+'_div');
        runDiv.addClass('row');

        var nameSpan = $('<span></span>');
        nameSpan.addClass('column');
        nameSpan.addClass('_25');
        nameSpan.text(name);

        var startSpan = $('<span></span>');
        startSpan.addClass('column');
        startSpan.addClass('_25');
        startSpan.text(start.toString().split(' ').splice(1, 4).join(' '));

        if(type != 'active') {
            var endSpan = $('<span></span>');
            endSpan.addClass('column');
            endSpan.addClass('_25');
            endSpan.text(end.toString().split(' ').splice(1, 4).join(' '));
        }

        var showSpan = $('<span></span>');
        showSpan.addClass('column');
        showSpan.addClass('_25');
        var showLink = $('<a></a>');
        showLink.attr('href', '#');

        var sysId = run['system'];
        var progId = run['program'];
        var runId = run['_id'];
        showLink.on('click', initShowLink(sysId, progId, runId));
        
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
        }
    });

    setTimeout(function() {
        runStats(runId);
    }, 3000);
}