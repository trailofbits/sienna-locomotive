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
        .y(function(d) { return vis.y(d.execs_per_sec); });
}

function visualizeStats() {
    console.log('vis');
    // unix_time
    // execs_per_sec
    // paths_total
    // unique_crashes
    vis.x.domain(d3.extent(vis.data, function(d) { return d.date; }));
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execs_per_sec; }));

    vis.axisBottom = vis.g.append("g");
    vis.axisBottom
      .attr("transform", "translate(0," + vis.height + ")")
      .call(d3.axisBottom(vis.x))
    .select(".domain")
      .remove();

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
    console.log('update');
    vis.x.domain(d3.extent(vis.data, function(d) { return d.date; }));
    vis.y.domain(d3.extent(vis.data, function(d) { return d.execs_per_sec; }));

    vis.axisLeft
        .transition()
        .duration(750)
        .call(d3.axisLeft(vis.y));

    vis.axisBottom
        .transition()
        .select(".domain")
            .remove()
        .duration(750)
        .call(d3.axisBottom(vis.x));

    vis.path
        .transition()
        .duration(750)
        .attr('d', vis.line(vis.data));
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
            if('error' in data) {
                handleError(data);
                return;
            } 

            var empty = true;
            for(var idx in data) {
                if(data[idx].length > 0) {
                    empty = false;
                    break;
                }
            }

            if(empty)
                return;


            for(var widx in data) {
                var worker_stats = data[widx];
                for(sidx in worker_stats) {
                    var unix = worker_stats[sidx]['stats'].unix_time;
                    var execs = parseInt(worker_stats[sidx]['stats'].execs_per_sec);
                    worker_stats[sidx]['stats'].date = new Date(unix * 1000);
                    worker_stats[sidx]['stats'].execs_per_sec = execs;
                    worker_stats[sidx] = worker_stats[sidx]['stats'];
                }
            }

            vis.data = data[0];


            if($('svg').children().children().length == 0) {
                visualizeStats(data);
            } else {
                updateVisualize(data);
            }
        }
    });

    setTimeout(function() {
        runStats(runId);
    }, 3000);
}