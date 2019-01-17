# -*- coding: utf-8 -*-

"""
bus2wp.py

copyright (c) ant21(libsoft@gmail.com)

This is a free software. It's destributed under the terms of GPL.

This program is use to convert xml file exported by blogbus to
wordpress extended rss file (WXR) with all comments, categories
and tags remained.

Notice it runs with Python 2 only.
"""

import re, sys, getopt, datetime
from xml.dom import minidom

def usage():
    print """
Usage: bus2wp.py [options] inputFile outputFile

-a --admin        Admin name. You should specify it if your post contains
                  admin reply comment. Default value is 'admin'.
-e --email        Admin email address. You should specify it if your post
                  contains admin reply comment.
-t --timediff     Time difference. Use it to convert the local time
                  to utc time. Specify it in formatting like '-6:30'.
                  If timediff is specified, the corresponding tags
                  "<pubDate>", "<wp:post_date_gmt>" and "<wp:comment_date_gmt>"
                  will be generated. Otherwise these tags will not be
                  generated. The produced WXR file can be imported without
                  these tags.
-o --order        Output order of your blog items.
                  Order is 'asc' or 'desc'. Default value is 'asc'.
-c --commentid    Start index of your comment id. Default value is 1.
                  Use this option to specify comment id if you have
                  WordPress posts and comments existed already.
-v --version      Display version info.
-h --help         Show help message.

examples:

    # convert blogbus xml file to wordpress WXR file.
    python bus2wp.py bus.xml wp.xml

    # specify admin name and email address.
    python bus2wp.py -a 'admin' -e 'admin@example.com' bus.xml wp.xml

    # specify time difference.
    python bus2wp.py -t +1:00 bus.xml wp.xml

    # specify converted items with DESC order.
    python bus2wp.py -o desc bus.xml wp.xml

    # specify comment id start from 917.
    python bus2wp.py -c 917 bus.xml wp.xml
    """
    sys.exit(0)

VERSION = '0.12.1208'
ADMIN_NAME = 'admin'
ADMIN_EMAIL = ''
TIME_DIFF = ''

def convert(inputFileName='bus.xml', outputFileName='wp.xml', order='asc'):
    """"""
    try:
        xmldoc = minidom.parse(inputFileName)
    except Exception, e:
        print 'Failed.'
        print e
        if '(invalid' and 'token):' in e.message.split():
            print 'Please repair or delete invalid token like "& < >" there.'
        sys.exit(1)

    bus = xmldoc.documentElement
    logs = bus.getElementsByTagName('blog')
    impl = minidom.getDOMImplementation()
    dom = impl.createDocument(None, 'rss', None)
    dom.firstChild.setAttribute('version', '2.0')
    dom.firstChild.setAttribute('xmlns:excerpt', 'http://wordpress.org/export/1.1/excerpt/')
    dom.firstChild.setAttribute('xmlns:content', 'http://purl.org/rss/1.0/modules/content/')
    dom.firstChild.setAttribute('xmlns:wfw', 'http://wellformedweb.org/CommentAPI/')
    dom.firstChild.setAttribute('xmlns:dc', 'http://purl.org/dc/elements/1.1/')
    dom.firstChild.setAttribute('xmlns:wp', 'http://wordpress.org/export/1.1/')
    channel = dom.createElement('channel')
    root = dom.documentElement
    root.appendChild(channel)

    # handle wxr_version
    channel.appendChild(createElement(dom, 'wp:wxr_version', '1.1'))

    # handle blog title
#    blogname = bus.getElementsByTagName('BlogName')[0]
#    channel.appendChild(createElement(dom, 'title', getElementData(blogname)))

    # Create a list to contain items instead of appending them to
    # channel directly in order to sort them lately according to order.
    item_list = [] if order == 'desc' else None

    print

    idx = 0
    for log in logs:
        title = log.getElementsByTagName('title')[0]
        title_text = getElementData(title)
        content = log.getElementsByTagName('content')[0]
        content_text = getElementData(content)
#        excerpt = log.getElementsByTagName('Excerpt')[0]
        excerpt_text = None
        # LogDate is a local time in blugbus
        logdate = log.getElementsByTagName('publishTime')[0]
        pubdate = "%d" % (long(getElementData(logdate)) / 1000) # local time
        writer = log.getElementsByTagName('userName')[0]
        creator = getElementData(writer)
        # blogbus supports only one category per post
        category = log.getElementsByTagName('className')[0]
        category_text = getElementData(category)
#        tags = log.getElementsByTagName('Tags')[0]
#        if len(getElementData(tags).strip()) != 0:
#            tag_list = getElementData(tags).split(' ')
#        else:
#            tag_list = None
        tag_list = None
        comments = None # log.getElementsByTagName('Comment')

        # create item element
        item = dom.createElement('item')

        # handle title
        title_element = createElement(dom, 'title', title_text)
        item.appendChild(title_element)

        # handle pubdate; a utc time in wordpress
        #
        # without pubdate wordpress will generate it automatically
        # test under WordPress 3.3.1
        if TIME_DIFF:
            pubdate_element = createElement(dom, 'pubDate',
                toUTC(pubdate, TIME_DIFF, z=True))
            item.appendChild(pubdate_element)

        # handle creator
        creator_element = createElement(dom, 'dc:creator', creator)
        item.appendChild(creator_element)

        # handle content
        content_element = createElement(dom, "content:encoded",
            content_text, 'cdata')
        item.appendChild(content_element)

        # handle excerpt
        if excerpt_text:
            excerpt_element = createElement(dom, "excerpt:encoded",
                excerpt_text, 'cdata')
            item.appendChild(excerpt_element)

        # handle post_date; a local time in wordpress
        #
        # Without post_date wordpress will use current local time
        # when the post is imported into database as its value.
        # Therefore, you should set the right time difference before
        # importing posts in wordpress.
        # test under WordPress 3.3.1
#        post_date_element = createElement(dom, "wp:post_date", pubdate)
#        item.appendChild(post_date_element)

        # handle post_date_gmt
        #
        # without post_date_gmt wordpress will generate it automatically
        # test under WordPress 3.3.1
        if TIME_DIFF:
            post_date_gmt_element = createElement(dom, "wp:post_date_gmt",
                toUTC(pubdate, TIME_DIFF, format_to='%Y-%m-%d %H:%M:%S'))
            item.appendChild(post_date_gmt_element)

        # handle status
        status_element = createElement(dom, "wp:status", 'publish')
        item.appendChild(status_element)

        # handle post type
        post_type_element = createElement(dom, "wp:post_type", 'post')
        item.appendChild(post_type_element)

##        #
##        # wxr version 1.0
##        #
##        # handle category
##        if category_text:
##            category_element = createElement(dom, 'category',
##                category_text, 'cdata')
##            item.appendChild(category_element)
##            category_element2 = createElement(dom, 'category',
##                category_text, 'cdata')
##            category_element2.setAttribute('domain', 'category')
##            category_element2.setAttribute('nicename', category_text)
##            item.appendChild(category_element2)
##
##        #
##        # wxr version 1.0
##        #
##        # handle tags
##        if tag_list:
##            for tag in tag_list:
##                tag_element = createElement(dom, 'category', tag, 'cdata')
##                tag_element.setAttribute('domain', 'tag')
##                item.appendChild(tag_element)
##                tag_element2 = createElement(dom, 'category', tag, 'cdata')
##                tag_element2.setAttribute('domain', 'tag')
##                tag_element2.setAttribute('nicename', tag)
##                item.appendChild(tag_element2)

        #
        # wxr version 1.1
        #
        # handle category
        if category_text:
            category_element = createElement(dom, 'category',
                category_text, 'cdata')
            category_element.setAttribute('domain', 'category')
            category_element.setAttribute('nicename', category_text)
            item.appendChild(category_element)

        #
        # wxr version 1.1
        #
        # handle tags
        if tag_list:
            for tag in tag_list:
                tag_element = createElement(dom, 'category', tag, 'cdata')
                tag_element.setAttribute('domain', 'post_tag')
                tag_element.setAttribute('nicename', tag)
                item.appendChild(tag_element)

        # handle comments
        if comments:
            commentElements = createComments(dom, comments)
            for commentElement in commentElements:
                item.appendChild(commentElement)

        if item_list != None:
            item_list.append(item)
        else:
            channel.appendChild(item)

        idx += 1
        per = idx/float(len(logs)) * 100
        progressStr = '\r[%.2f%%] Total Posts %d Converted %d' % (
            per, len(logs), idx,)
        sys.stdout.write(progressStr)
        sys.stdout.flush()

    if item_list:
        item_list.reverse()
        for m in item_list:
            channel.appendChild(m)

    writeDomToFile(dom, outputFileName)

def getElementData(element):
    """"""
    data = ''
    for node in element.childNodes:
        if node.nodeType in (node.TEXT_NODE, node.CDATA_SECTION_NODE):
            data += node.data
    return data

def createComments(dom, comments):
    """"""
    l = []
    for comment in comments:
        email = comment.getElementsByTagName('Email')[0]
        homepage = comment.getElementsByTagName('HomePage')[0]

        # blogbus SchemaVersion = "1.0-b" has "PostIP" tag.
        # blogbus SchemaVersion = "1.1" has no "PostIP" tag.
        try:
            ip = comment.getElementsByTagName('PostIP')[0]
        except:
            ip = None

        name = comment.getElementsByTagName('NiceName')[0]
        content = comment.getElementsByTagName('CommentText')[0]
        date = comment.getElementsByTagName('CreateTime')[0]

        try:
            admin_reply = comment.getElementsByTagName('Reply')[0]
        except:
            admin_reply = None

        ce = createCommentElement(dom, email, homepage, name, content, date,
                ip=ip, admin_reply=admin_reply)

        if admin_reply:
            comment_element, comment_parent_element = ce
        else:
            comment_element = ce
            comment_parent_element = None

        l.append(comment_element)
        if comment_parent_element:
            l.append(comment_parent_element)
    return l

def createCommentElement(dom, email, homepage, name, content, date,
        ip=None, admin_reply=None, comment_parent='0'):
    """"""
    # prepare comment data
    comment_id = str(commentID.next())
    comment_author = getElementData(name)
    comment_author_email = getElementData(email)
    comment_author_url = getElementData(homepage)
    comment_author_ip = getElementData(ip) if ip else None
    comment_date = getElementData(date)
    comment_content = getElementData(content)

    # create comment xml elements

    # for WP 2.9.1 there is comment_id element
    comment_id_element = createElement(dom,
        'wp:comment_id', comment_id)
    comment_author_element = createElement(dom,
        'wp:comment_author', comment_author)
    comment_author_email_element = createElement(dom,
        'wp:comment_author_email', comment_author_email)
    comment_author_url_element = createElement(dom,
        'wp:comment_author_url', comment_author_url)
    comment_author_ip_element = createElement(dom,
        'wp:comment_author_IP', comment_author_ip) if comment_author_ip else None
    comment_date_element = createElement(dom,
        'wp:comment_date', comment_date)
    if TIME_DIFF:
        comment_date_gmt_element = createElement(dom,
            'wp:comment_date_gmt', toUTC(comment_date, TIME_DIFF,
                format_to='%Y-%m-%d %H:%M:%S'))
    comment_content_element = createElement(dom,
        'wp:comment_content', comment_content, 'cdata')
    comment_approved_element = createElement(dom,
        'wp:comment_approved', '1')
    comment_type_element = createElement(dom,
        'wp:comment_type', '')
    comment_parent_element = createElement(dom,
        'wp:comment_parent', comment_parent)

    # make the comment element
    comment_element = dom.createElement('wp:comment')

    # add elements to comment
    comment_element.appendChild(comment_id_element)
    comment_element.appendChild(comment_author_element)
    if validateEmail(comment_author_email):
        comment_element.appendChild(comment_author_email_element)
    if validateUrl(comment_author_url):
        comment_element.appendChild(comment_author_url_element)
    if comment_author_ip and validateIP(comment_author_ip):
        comment_element.appendChild(comment_author_ip_element)
    comment_element.appendChild(comment_date_element)
    # without comment_date_gmt wordpress will generate it automatically
    # test under WordPress 3.3.1
    if TIME_DIFF:
        comment_element.appendChild(comment_date_gmt_element)
    comment_element.appendChild(comment_content_element)
    comment_element.appendChild(comment_approved_element)
    comment_element.appendChild(comment_type_element)
    comment_element.appendChild(comment_parent_element)

    # if the comment contains admin_reply; make it a comment element
    if admin_reply:
        reply_text = admin_reply.getElementsByTagName('ReplyText')[0]
        reply_time = admin_reply.getElementsByTagName('ReplyTime')[0]
        reply_ip = admin_reply.getElementsByTagName('ReplyIp')[0]
        comment_parent_element = createCommentElement(dom,
            createElement(dom, 'ADMIN_EMAIL', ADMIN_EMAIL),
            createElement(dom, 'url', ''),
            createElement(dom, 'ADMIN_NAME', ADMIN_NAME),
            reply_text, reply_time,
            ip=reply_ip, admin_reply=None, comment_parent=comment_id)
        return (comment_element, comment_parent_element)
    return comment_element

def createElement(dom, elementName, elementValue, type='text'):
    """"""
    tag = dom.createElement(elementName)
    if elementValue.find(']]>') > -1:
        type = 'text'
    if type == 'text':
        elementValue = elementValue.replace('&', '&amp;')
        elementValue = elementValue.replace('<', '&lt;')
        elementValue = elementValue.replace('>', '&gt;')
        elementValue = elementValue.replace('\'', '&apos;')
        elementValue = elementValue.replace('"', '&quot;')

        text = dom.createTextNode(elementValue)
    elif type == 'cdata':
        text = dom.createCDATASection(elementValue)
    tag.appendChild(text)
    return tag

def counter(i=1):
    while True:
        val = (yield i)
        if val is not None:
            i = val
        else:
            i += 1
commentID = counter()

def toUTC(date, timediff,
            format_from='%Y-%m-%d %H:%M:%S',
            format_to='%a, %d %b %Y %H:%M:%S',
            z=False):
    """Convert local time to UTC time.

    Default format: 2009-08-22 19:55:08 -> Sat, 22 Aug 2009 19:55:08

    Timediff format should be '+8:30', '-8:45' etc.
    """
    td = timediff.split(':')
    h = int(td[0])
    m = int(td[1]) if len(td) == 2 else 0
    if h > 14 or h < -12 or m not in (0, 30, 45):
        raise Exception('Time diff "%s" is not corrent.' % timediff)
    delta = datetime.timedelta(hours=h, minutes=m)
    lt = datetime.datetime.fromtimestamp(float(date)) # datetime.datetime.strptime(date, format_from)
    ut = lt - delta
    if z: # show '+0000'
        return '%s %s' % (ut.strftime(format_to), '+0000')
    return ut.strftime(format_to)

def validateIP(ip):
    #[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
    pattern = r'^([01]?\d\d?|2[0-4]\d|25[0-5])(\.([01]?\d\d?|2[0-4]\d|25[0-5])){3}$'
    p = re.compile(pattern)
    m = p.match(ip)
    if m:
        return True
    return False

def validateEmail(email):
    pattern = r'^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$'
    p = re.compile(pattern)
    m = p.match(email)
    if m:
        return True
    return False

def validateUrl(url):
    pattern = r'^[a-zA-z]+://(\w+(-\w+)*)(\.(\w+(-\w+)*))*(\?\S*)?$'
    p = re.compile(pattern)
    m = p.match(url)
    if m:
        return True
    return False

def makeIndent(dom, node, indent=0):
    TAB = ' ' * 4
    NEWLINE = '\n'
    # Copy child list because it will change soon.
    children = node.childNodes[:]
    # Main node doesn't need to be indented.
    if indent:
        text = dom.createTextNode(NEWLINE + TAB * indent)
        node.parentNode.insertBefore(text, node)
    if children:
        # Append newline after last child; except for text nodes.
       if children[-1].nodeType == node.ELEMENT_NODE:
           text = dom.createTextNode(NEWLINE + TAB * indent)
           node.appendChild(text)
       # Indent children which are elements.
       for n in children:
           if n.nodeType == node.ELEMENT_NODE:
               makeIndent(dom, n, indent + 1)

def writeDomToFile(dom, filename):
    domcopy = dom.cloneNode(True)
    makeIndent(domcopy, domcopy.documentElement)
    f = file(filename, 'wb')
    import codecs
    writer = codecs.lookup('utf-8')[3](f)
    domcopy.writexml(writer, encoding='utf-8')
    domcopy.unlink()
    writer.close()

def main(argv=None):
    global ADMIN_NAME, ADMIN_EMAIL, TIME_DIFF

    if argv is None:
        argv = sys.argv
    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "a:e:t:o:c:hv",
            ["admin=", "email=", "order=", "timediff=",
             "commentid=", "help", "version"])
    except getopt.error, msg:
        print msg
        print "for help use --help"
        sys.exit(2)

    # process options
    order = None
    for o, a in opts:
        if o in ("-a", "--admin"):
            ADMIN_NAME = a
        elif o in ("-e", "--email"):
            ADMIN_EMAIL = a
        elif o in ("-t", "--timediff"):
            td = a.split(':')
            h = int(td[0])
            m = int(td[1]) if len(td) == 2 else 0
            if h > 14 or h < -12 or m not in (0, 30, 45):
                print 'Time diff "%s" is not corrent.' % a
                sys.exit(2)
            TIME_DIFF = a
        elif o in ("-o", "--order"):
            if a.lower() == 'asc' or a.lower() == 'desc':
                order = a
            else:
                usage()
        elif o in ("-c", "--commentid"):
            if a.isdigit():
                commentID.next()
                commentID.send(int(a)-1)
            else:
                print 'Comment id should be integer.'
                sys.exit(2)
        elif o in ("-h", "--help"):
            usage()
        elif o in ("-v", "--version"):
            print VERSION
            sys.exit(0)
    # process arguments
    if (len(args) == 2):
        print 'Converting...',
        start = datetime.datetime.now()
        convert(args[0], args[1], order)
        end = datetime.datetime.now()
        print
        print 'Done. Elapse %d seconds.' % (end - start).seconds
    else:
        usage()

if __name__ == "__main__":
    sys.exit(main())
