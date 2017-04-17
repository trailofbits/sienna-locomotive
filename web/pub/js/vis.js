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
}

function visualizeStats() {
    console.log('vis');
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
        var stats = stats[idx];

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

function runStats(runId) {
    var checkId = $('#run_select').val();
    
    if(runId == undefined) {
        $('svg').children().empty();
        runId = checkId;
    }

    if(runId != checkId)
        return;

    $.ajax({
        type: 'GET',
        url: '/run_stats_all/' + runId, 
        success: function(data) {
            data = JSON.parse(data);
            datas = data;
            if('error' in data) {
                handleError(data);
                return;
            } 

            var recentStats = runStatsSuccess(data['stats']);
            runStatusSuccess(data['status'], recentStats);
        }
    });

    // setTimeout(function() {
    //     runStats(runId);
    // }, 3000);
}