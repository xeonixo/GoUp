package httpserver

import (
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"strings"
)

func (s *Server) renderDashboardTemplateFragment(name string, data pageData) (string, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return "", fmt.Errorf("dashboard template not found")
	}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, name, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (s *Server) renderDashboardLiveSnapshotResponse(data pageData) (dashboardLiveSnapshotResponse, error) {
	tmpl, ok := s.templates["dashboard"]
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard template not found")
	}

	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "layout", data); err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	doc, err := html.Parse(strings.NewReader(out.String()))
	if err != nil {
		return dashboardLiveSnapshotResponse{}, err
	}

	statsHTML, ok := outerHTMLByID(doc, "dashboard-live-stats")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard stats fragment not found")
	}
	boardHTML, ok := outerHTMLByID(doc, "dashboard-live-board")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard board fragment not found")
	}
	boardNode := htmlNodeByID(doc, "dashboard-live-board")
	boardGroupsHTML, boardGroupOrder := boardClustersByGroup(boardNode)
	boardGroupHashes := make(map[string]string, len(boardGroupsHTML))
	for group, fragment := range boardGroupsHTML {
		boardGroupHashes[group] = hashDashboardFragment(fragment)
	}
	stateEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-state-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard state events fragment not found")
	}
	notificationEventsHTML, ok := outerHTMLByID(doc, "dashboard-live-notification-events")
	if !ok {
		return dashboardLiveSnapshotResponse{}, fmt.Errorf("dashboard notification events fragment not found")
	}
	groupOptionsHTML, ok := innerHTMLByID(doc, "monitor-group-options")
	if !ok {
		groupOptionsHTML = ""
	}

	return dashboardLiveSnapshotResponse{
		StatsHTML:              statsHTML,
		BoardHTML:              boardHTML,
		BoardGroupsHTML:        boardGroupsHTML,
		StateEventsHTML:        stateEventsHTML,
		NotificationEventsHTML: notificationEventsHTML,
		GroupOptionsHTML:       groupOptionsHTML,
		StatsHash:              hashDashboardFragment(statsHTML),
		BoardHash:              hashDashboardFragment(boardHTML),
		BoardGroupsHash:        boardGroupHashes,
		StateEventsHash:        hashDashboardFragment(stateEventsHTML),
		NotificationEventsHash: hashDashboardFragment(notificationEventsHTML),
		GroupOptionsHash:       hashDashboardFragment(groupOptionsHTML),
		BoardGroupHashes:       boardGroupHashes,
		BoardGroupOrder:        boardGroupOrder,
	}, nil
}

func boardClustersByGroup(boardNode *html.Node) (map[string]string, []string) {
	if boardNode == nil {
		return nil, nil
	}

	groups := make(map[string]string)
	order := make([]string, 0, 16)
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node == nil {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "details") && htmlHasClass(node, "service-cluster") {
			group := htmlAttr(node, "data-group")
			if group != "" {
				var buf bytes.Buffer
				if err := html.Render(&buf, node); err == nil {
					groups[group] = buf.String()
					order = append(order, group)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(boardNode)
	if len(groups) == 0 {
		return nil, nil
	}
	return groups, order
}

func htmlHasClass(node *html.Node, className string) bool {
	if node == nil || className == "" {
		return false
	}
	for _, attr := range node.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, value := range strings.Fields(attr.Val) {
			if value == className {
				return true
			}
		}
	}
	return false
}

func htmlAttr(node *html.Node, key string) string {
	if node == nil || key == "" {
		return ""
	}
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func outerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, node); err != nil {
		return "", false
	}
	return buf.String(), true
}

func innerHTMLByID(root *html.Node, id string) (string, bool) {
	node := htmlNodeByID(root, id)
	if node == nil {
		return "", false
	}
	var buf bytes.Buffer
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := html.Render(&buf, child); err != nil {
			return "", false
		}
	}
	return buf.String(), true
}

func htmlNodeByID(node *html.Node, id string) *html.Node {
	if node == nil {
		return nil
	}
	if node.Type == html.ElementNode {
		for _, attr := range node.Attr {
			if attr.Key == "id" && attr.Val == id {
				return node
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if match := htmlNodeByID(child, id); match != nil {
			return match
		}
	}
	return nil
}
