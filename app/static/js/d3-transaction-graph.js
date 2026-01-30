/**
 * D3.js Transaction Graph Visualization
 * CyberTrace OSINT Platform - Zambia Police Service
 *
 * Renders force-directed graph for financial transaction flows
 * and cryptocurrency transaction tracing.
 */

function renderTransactionGraph(containerId, graphData) {
    const container = document.getElementById(containerId);
    if (!container || !graphData) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 600;

    // Clear previous
    d3.select('#' + containerId).selectAll('*').remove();

    const svg = d3.select('#' + containerId)
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Arrow marker for directed edges
    svg.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '-0 -5 10 10')
        .attr('refX', 25)
        .attr('refY', 0)
        .attr('orient', 'auto')
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .append('path')
        .attr('d', 'M 0,-5 L 10,0 L 0,5')
        .attr('fill', '#999');

    const nodes = graphData.nodes || [];
    const links = graphData.links || [];

    // Color scale for node types
    const colorScale = {
        'source': '#28a745',
        'destination': '#dc3545',
        'mule': '#ffc107',
        'normal': '#007bff',
        'exchange': '#6f42c1'
    };

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(120))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(35));

    // Zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.2, 5])
        .on('zoom', (event) => g.attr('transform', event.transform));
    svg.call(zoom);

    const g = svg.append('g');

    // Links
    const link = g.append('g')
        .selectAll('line')
        .data(links)
        .enter().append('line')
        .attr('stroke', d => d.suspicious ? '#dc3545' : '#999')
        .attr('stroke-opacity', 0.6)
        .attr('stroke-width', d => Math.max(1, Math.min(8, (d.amount || 1) / 1000)))
        .attr('marker-end', 'url(#arrowhead)');

    // Link labels (amounts)
    const linkLabel = g.append('g')
        .selectAll('text')
        .data(links)
        .enter().append('text')
        .attr('font-size', '10px')
        .attr('fill', '#666')
        .attr('text-anchor', 'middle')
        .text(d => d.label || '');

    // Nodes
    const node = g.append('g')
        .selectAll('g')
        .data(nodes)
        .enter().append('g')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    // Node circles
    node.append('circle')
        .attr('r', d => d.is_mule ? 20 : (d.transaction_count ? Math.min(18, 8 + d.transaction_count) : 12))
        .attr('fill', d => colorScale[d.type] || colorScale['normal'])
        .attr('stroke', d => d.is_mule ? '#dc3545' : '#fff')
        .attr('stroke-width', d => d.is_mule ? 3 : 2)
        .style('cursor', 'pointer');

    // Node labels
    node.append('text')
        .attr('dy', 30)
        .attr('text-anchor', 'middle')
        .attr('font-size', '11px')
        .attr('fill', '#333')
        .text(d => d.label || d.id);

    // Mule warning icon
    node.filter(d => d.is_mule)
        .append('text')
        .attr('dy', -25)
        .attr('text-anchor', 'middle')
        .attr('font-size', '14px')
        .attr('fill', '#dc3545')
        .text('MULE');

    // Tooltip
    node.append('title')
        .text(d => {
            let tip = d.label || d.id;
            if (d.holder_name) tip += '\nHolder: ' + d.holder_name;
            if (d.total_inflow) tip += '\nInflow: ZMW ' + d.total_inflow.toLocaleString();
            if (d.total_outflow) tip += '\nOutflow: ZMW ' + d.total_outflow.toLocaleString();
            if (d.risk_score) tip += '\nRisk: ' + d.risk_score + '/100';
            return tip;
        });

    // Tick
    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        linkLabel
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);

        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // Legend
    const legend = svg.append('g')
        .attr('transform', 'translate(20, 20)');

    const legendItems = [
        { label: 'Normal Account', color: colorScale['normal'] },
        { label: 'Source', color: colorScale['source'] },
        { label: 'Destination', color: colorScale['destination'] },
        { label: 'Mule Account', color: colorScale['mule'] },
        { label: 'Exchange', color: colorScale['exchange'] }
    ];

    legendItems.forEach((item, i) => {
        const row = legend.append('g').attr('transform', `translate(0, ${i * 22})`);
        row.append('rect')
            .attr('width', 14).attr('height', 14)
            .attr('rx', 3).attr('fill', item.color);
        row.append('text')
            .attr('x', 20).attr('y', 12)
            .attr('font-size', '12px').attr('fill', '#333')
            .text(item.label);
    });
}
