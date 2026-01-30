/**
 * D3.js Network Visualization
 * CyberTrace OSINT Platform - Zambia Police Service
 *
 * Renders network graph for cross-case correlation analysis.
 * Shows cases as nodes and shared indicators as edges.
 */

function renderNetworkGraph(containerId, networkData) {
    const container = document.getElementById(containerId);
    if (!container || !networkData) return;

    const width = container.clientWidth;
    const height = container.clientHeight || 600;

    d3.select('#' + containerId).selectAll('*').remove();

    const svg = d3.select('#' + containerId)
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const nodes = networkData.nodes || [];
    const links = networkData.links || [];

    // Node types: case, indicator, actor
    const colorScale = {
        'case': '#007bff',
        'indicator': '#28a745',
        'actor': '#dc3545',
        'phone': '#6f42c1',
        'email': '#fd7e14',
        'ip': '#20c997',
        'domain': '#e83e8c',
        'crypto': '#ffc107'
    };

    const iconScale = {
        'case': '\uf07b',
        'phone': '\uf095',
        'email': '\uf0e0',
        'ip': '\uf6ff',
        'domain': '\uf0ac',
        'crypto': '\uf15a',
        'actor': '\uf21b'
    };

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

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
        .attr('stroke', d => {
            const conf = d.confidence || 50;
            if (conf >= 80) return '#dc3545';
            if (conf >= 60) return '#ffc107';
            return '#adb5bd';
        })
        .attr('stroke-opacity', 0.7)
        .attr('stroke-width', d => Math.max(1, (d.confidence || 50) / 25))
        .attr('stroke-dasharray', d => (d.confidence || 50) < 50 ? '5,5' : 'none');

    // Link labels
    const linkLabel = g.append('g')
        .selectAll('text')
        .data(links)
        .enter().append('text')
        .attr('font-size', '9px')
        .attr('fill', '#888')
        .attr('text-anchor', 'middle')
        .text(d => d.indicator_type || '');

    // Nodes
    const node = g.append('g')
        .selectAll('g')
        .data(nodes)
        .enter().append('g')
        .style('cursor', 'pointer')
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended));

    node.append('circle')
        .attr('r', d => d.type === 'case' ? 18 : (d.type === 'actor' ? 22 : 10))
        .attr('fill', d => colorScale[d.type] || colorScale[d.indicator_type] || '#6c757d')
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);

    node.append('text')
        .attr('dy', d => d.type === 'case' ? 30 : 22)
        .attr('text-anchor', 'middle')
        .attr('font-size', d => d.type === 'case' ? '11px' : '9px')
        .attr('fill', '#333')
        .attr('font-weight', d => d.type === 'case' ? 'bold' : 'normal')
        .text(d => d.label || d.id);

    // Case node inner text
    node.filter(d => d.type === 'case')
        .append('text')
        .attr('dy', 5)
        .attr('text-anchor', 'middle')
        .attr('font-size', '10px')
        .attr('fill', '#fff')
        .attr('font-weight', 'bold')
        .text(d => d.case_number ? d.case_number.split('-').pop() : '');

    node.append('title')
        .text(d => {
            let tip = d.label || d.id;
            if (d.case_number) tip += '\nCase: ' + d.case_number;
            if (d.indicator_type) tip += '\nType: ' + d.indicator_type;
            if (d.match_count) tip += '\nMatches: ' + d.match_count;
            return tip;
        });

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
        d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
    function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }

    // Legend
    const legend = svg.append('g').attr('transform', 'translate(20, 20)');
    const items = [
        { label: 'Case', color: colorScale['case'] },
        { label: 'Threat Actor', color: colorScale['actor'] },
        { label: 'Phone', color: colorScale['phone'] },
        { label: 'Email', color: colorScale['email'] },
        { label: 'IP Address', color: colorScale['ip'] },
        { label: 'Domain', color: colorScale['domain'] },
        { label: 'Crypto', color: colorScale['crypto'] }
    ];
    items.forEach((item, i) => {
        const row = legend.append('g').attr('transform', `translate(0, ${i * 20})`);
        row.append('circle').attr('cx', 7).attr('cy', 7).attr('r', 6).attr('fill', item.color);
        row.append('text').attr('x', 20).attr('y', 11).attr('font-size', '11px').attr('fill', '#333').text(item.label);
    });
}
